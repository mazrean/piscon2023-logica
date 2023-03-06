package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/mazrean/isucon-go-tools"
	isucache "github.com/mazrean/isucon-go-tools/cache"
	isudb "github.com/mazrean/isucon-go-tools/db"
	isuhttp "github.com/mazrean/isucon-go-tools/http"
	isulocker "github.com/mazrean/isucon-go-tools/locker"
	"github.com/mazrean/isucon-go-tools/query"
	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
	"golang.org/x/sync/errgroup"
)

func main() {
	jst := time.FixedZone("Asia/Tokyo", 9*60*60)
	time.Local = jst

	host := getEnvOrDefault("DB_HOST", "localhost")
	port := getEnvOrDefault("DB_PORT", "3306")
	user := getEnvOrDefault("DB_USER", "isucon")
	pass := getEnvOrDefault("DB_PASS", "isucon")
	name := getEnvOrDefault("DB_NAME", "isulibrary")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FTokyo", user, pass, host, port, name)

	var err error
	db, err = isudb.DBMetricsSetup(sqlx.Open)("mysql", dsn)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	var key string
	err = db.Get(&key, "SELECT `key` FROM `key` WHERE `id` = (SELECT MAX(`id`) FROM `key`)")
	if err != nil {
		log.Panic(err)
	}

	block, err = aes.NewCipher([]byte(key))
	if err != nil {
		log.Panic(err)
	}

	e := isuhttp.EchoSetting(echo.New())
	e.Use(middleware.Logger())

	api := e.Group("/api")
	{
		api.POST("/initialize", initializeHandler)

		membersAPI := api.Group("/members")
		{
			membersAPI.POST("", postMemberHandler)
			membersAPI.GET("", getMembersHandler)
			membersAPI.GET("/:id", getMemberHandler)
			membersAPI.PATCH("/:id", patchMemberHandler)
			membersAPI.DELETE("/:id", banMemberHandler)
			membersAPI.GET("/:id/qrcode", getMemberQRCodeHandler)
		}

		booksAPI := api.Group("/books")
		{
			booksAPI.POST("", postBooksHandler)
			booksAPI.GET("", getBooksHandler)
			booksAPI.GET("/:id", getBookHandler)
			booksAPI.GET("/:id/qrcode", getBookQRCodeHandler)
		}

		lendingsAPI := api.Group("/lendings")
		{
			lendingsAPI.POST("", postLendingsHandler)
			lendingsAPI.GET("", getLendingsHandler)
			lendingsAPI.POST("/return", returnLendingsHandler)
		}
	}

	err = initMemberCache()
	if err != nil {
		panic(err)
	}

	err = initBookCache()
	if err != nil {
		panic(err)
	}

	err = initQRCode(true)
	if err != nil {
		panic(err)
	}

	e.Logger.Fatal(e.Start(":8080"))
}

/*
---------------------------------------------------------------
Domain Models
---------------------------------------------------------------
*/

// 会員
type Member struct {
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Address     string    `json:"address" db:"address"`
	PhoneNumber string    `json:"phone_number" db:"phone_number"`
	Banned      bool      `json:"banned" db:"banned"`
}

// 図書分類
type Genre int

// 国際十進分類法に従った図書分類
const (
	General         Genre = iota // 総記
	Philosophy                   // 哲学・心理学
	Religion                     // 宗教・神学
	SocialScience                // 社会科学
	Vacant                       // 未定義
	Mathematics                  // 数学・自然科学
	AppliedSciences              // 応用科学・医学・工学
	Arts                         // 芸術
	Literature                   // 言語・文学
	Geography                    // 地理・歴史
)

// 蔵書
type Book struct {
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ID        string    `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Author    string    `json:"author" db:"author"`
	Genre     Genre     `json:"genre" db:"genre"`
}

// 貸出記録
type Lending struct {
	Due       time.Time `json:"due" db:"due"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ID        string    `json:"id" db:"id"`
	MemberID  string    `json:"member_id" db:"member_id"`
	BookID    string    `json:"book_id" db:"book_id"`
}

/*
---------------------------------------------------------------
Utilities
---------------------------------------------------------------
*/

// ULIDを生成
func generateID() string {
	return ulid.Make().String()
}

var db *sqlx.DB

func getEnvOrDefault(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}

	return defaultValue
}

var (
	block cipher.Block
)

// AES + CTRモード + base64エンコードでテキストを暗号化
func encrypt(plainText string) (string, error) {
	cipherText := make([]byte, aes.BlockSize+len([]byte(plainText)))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

// AES + CTRモード + base64エンコードで暗号化されたテキストを複合
func decrypt(cipherText string) (string, error) {
	cipherByte, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	decryptedText := make([]byte, len([]byte(cipherByte[aes.BlockSize:])))
	decryptStream := cipher.NewCTR(block, []byte(cipherByte[:aes.BlockSize]))
	decryptStream.XORKeyStream(decryptedText, []byte(cipherByte[aes.BlockSize:]))
	return string(decryptedText), nil
}

const (
	qrCodeDirName     = "../images/qr"
	initQRCodeDirName = "../images/qr-init"
)

var (
	poolLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "id_pool_len",
		Help: "The length of id pool",
	})
	idPool = isulocker.NewValue([]string{}, "id_pool")
)

func initQRCode(initialize bool) error {
	err := os.MkdirAll(qrCodeDirName, 0755)
	if err != nil {
		return err
	}

	var ids []string
	err = db.Select(&ids, "SELECT id FROM book UNION SELECT id FROM member")
	if err != nil {
		return err
	}

	idPool.Write(func(s *[]string) {
		newS := make([]string, 0, 5000)
		for i := 0; i < 5000; i++ {
			id := generateID()
			newS = append(newS, id)
			ids = append(ids, id)
		}
		*s = newS
		poolLen.Set(float64(len(*s)))
	})

	idMap := make(map[string]struct{})
	for _, id := range ids {
		idMap[id] = struct{}{}
	}

	files, err := os.ReadDir(qrCodeDirName)
	if err != nil {
		return err
	}

	for _, file := range files {
		if _, ok := idMap[file.Name()]; !ok {
			err = os.Remove(filepath.Join(qrCodeDirName, file.Name()))
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}

	for _, id := range ids {
		err = func() error {
			_, err := os.Stat(filepath.Join(qrCodeDirName, fmt.Sprintf("%s.png", id)))
			if err == nil {
				return nil
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}

			dstF, err := os.Create(filepath.Join(qrCodeDirName, fmt.Sprintf("%s.png", id)))
			if err != nil {
				return err
			}
			defer dstF.Close()

			err = generateQRCode(id, dstF)
			if err != nil {
				return err
			}

			return nil
		}()
	}

	return err
}

type pngEncoder struct{}

func (j pngEncoder) Encode(w io.Writer, img image.Image) error {
	enc := png.Encoder{
		CompressionLevel: png.NoCompression,
	}

	return enc.Encode(w, img)
}

// QRコードを生成
func generateQRCode(id string, w io.WriteCloser) error {
	encryptedID, err := encrypt(id)
	if err != nil {
		return err
	}

	/*
		生成するQRコードの仕様
		 - PNGフォーマット
		 - QRコードの1モジュールは1ピクセルで表現
		 - バージョン5 (37x37ピクセル、マージン含め45x45ピクセル)
		 - エラー訂正レベルM (15%)
	*/
	qrc, err := qrcode.NewWith(
		encryptedID,
		qrcode.WithVersion(6),
		qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionMedium),
	)
	if err != nil {
		return err
	}

	sw := standard.NewWithWriter(
		w,
		standard.WithQRWidth(1),
		standard.WithBorderWidth(4),
		standard.WithCustomImageEncoder(pngEncoder{}),
	)
	err = qrc.Save(sw)
	if err != nil {
		return err
	}

	return nil
}

/*
---------------------------------------------------------------
Initialization API
---------------------------------------------------------------
*/

type InitializeHandlerRequest struct {
	Key string `json:"key"`
}

type InitializeHandlerResponse struct {
	Language string `json:"language"`
}

// 初期化用ハンドラ
func initializeHandler(c echo.Context) error {
	isucache.AllPurge()

	var req InitializeHandlerRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(req.Key) != 16 {
		return echo.NewHTTPError(http.StatusBadRequest, "key must be 16 characters")
	}

	cmd := exec.Command("sh", "../sql/init_db.sh")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, err = db.ExecContext(c.Request().Context(), "INSERT INTO `key` (`key`) VALUES (?)", req.Key)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	block, err = aes.NewCipher([]byte(req.Key))
	if err != nil {
		log.Panic(err.Error())
	}

	err = initMemberCache()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	err = initBookCache()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	err = initQRCode(false)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, InitializeHandlerResponse{
		Language: "Go",
	})
}

/*
---------------------------------------------------------------
Members API
---------------------------------------------------------------
*/

var (
	memberCache     = isucache.NewAtomicMap[string, *isulocker.Value[Member]]("member")
	memberNameCache = isucache.NewSlice("member_name", make([]*isulocker.Value[Member], 0, 5000), 5000)
	memberIDCache   = isucache.NewSlice("member_id", make([]*isulocker.Value[Member], 0, 5000), 5000)
)

func initMemberCache() error {
	var members []*Member
	err := db.Select(&members, "SELECT * FROM `member` ORDER BY `id` ASC")
	if err != nil {
		return fmt.Errorf("failed to get members: %w", err)
	}

	for _, member := range members {
		memberCache.Store(member.ID, isulocker.NewValue(*member, "member"))
	}

	memberValues := make([]*isulocker.Value[Member], 0, len(members))
	for _, member := range members {
		if !member.Banned {
			memberValue, ok := memberCache.Load(member.ID)
			if !ok {
				log.Printf("member not found in cache: %s\n", member.ID)
				continue
			}
			memberValues = append(memberValues, memberValue)
		}
	}
	memberIDCache.Append(memberValues...)

	sort.SliceStable(members, func(i, j int) bool {
		return members[i].Name < members[j].Name
	})
	memberValues = make([]*isulocker.Value[Member], 0, len(members))
	for _, member := range members {
		if !member.Banned {
			memberValue, ok := memberCache.Load(member.ID)
			if !ok {
				log.Printf("member not found in cache: %s\n", member.ID)
				continue
			}
			memberValues = append(memberValues, memberValue)
		}
	}
	memberNameCache.Append(memberValues...)

	return nil
}

type PostMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員登録
func postMemberHandler(c echo.Context) error {
	var req PostMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" || req.Address == "" || req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address, phoneNumber are required")
	}

	var id string
	idPool.Write(func(idPool *[]string) {
		if len(*idPool) != 0 {
			id = (*idPool)[0]
			*idPool = (*idPool)[1:]
			poolLen.Dec()
		} else {
			id = generateID()
		}
	})

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(c.Request().Context(),
		"INSERT INTO `member` (`id`, `name`, `address`, `phone_number`, `banned`, `created_at`) VALUES (?, ?, ?, ?, false, ?)",
		id, req.Name, req.Address, req.PhoneNumber, time.Now())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_ = tx.Commit()

	res := Member{
		ID:          id,
		Name:        req.Name,
		Address:     req.Address,
		PhoneNumber: req.PhoneNumber,
		Banned:      false,
		CreatedAt:   time.Now(),
	}
	memberValue := isulocker.NewValue(res, "member")
	memberCache.Store(id, memberValue)
	memberIDCache.Edit(func(members []*isulocker.Value[Member]) []*isulocker.Value[Member] {
		members = append(members, memberValue)
		sort.SliceStable(members, func(i, j int) bool {
			var result bool
			members[i].Read(func(memberI *Member) {
				members[j].Read(func(memberJ *Member) {
					result = memberI.ID < memberJ.ID
				})
			})
			return result
		})
		return members
	})
	memberNameCache.Edit(func(members []*isulocker.Value[Member]) []*isulocker.Value[Member] {
		members = append(members, memberValue)
		sort.SliceStable(members, func(i, j int) bool {
			var result bool
			members[i].Read(func(memberI *Member) {
				members[j].Read(func(memberJ *Member) {
					result = memberI.Name < memberJ.Name
				})
			})
			return result
		})
		return members
	})

	return c.JSON(http.StatusCreated, res)
}

const memberPageLimit = 100

type GetMembersResponse struct {
	Members []*Member `json:"members"`
	Total   int       `json:"total"`
}

// 会員一覧を取得 (ページネーションあり)
func getMembersHandler(c echo.Context) error {
	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	start := (page - 1) * memberPageLimit
	end := start + memberPageLimit
	if (page-1)*memberPageLimit >= memberIDCache.Len() {
		return echo.NewHTTPError(http.StatusNotFound, "no members to show in this page")
	}
	if end > memberIDCache.Len() {
		end = memberIDCache.Len()
	}

	// 前ページの最後の会員ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_member_id")

	var members []*Member
	order := c.QueryParam("order")
	switch order {
	case "":
		members = make([]*Member, 0, memberPageLimit)
		memberIDCache.Slice(start, end, func(s []*isulocker.Value[Member]) {
			for _, v := range s {
				var member Member
				v.Read(func(m *Member) {
					member = *m
				})
				members = append(members, &member)
			}
		})
	case "name_asc":
		members = make([]*Member, 0, memberPageLimit)
		memberNameCache.Slice(start, end, func(s []*isulocker.Value[Member]) {
			for _, v := range s {
				var member Member
				v.Read(func(m *Member) {
					member = *m
				})
				members = append(members, &member)
			}
		})
	case "name_desc":
		start, end = memberNameCache.Len()-end, memberNameCache.Len()-start
		tmpMembers := make([]*Member, 0, memberPageLimit)
		memberNameCache.Slice(start, end, func(s []*isulocker.Value[Member]) {
			for _, v := range s {
				var member Member
				v.Read(func(m *Member) {
					member = *m
				})
				tmpMembers = append(tmpMembers, &member)
			}
		})

		members = make([]*Member, len(tmpMembers))
		for i, v := range tmpMembers {
			members[len(tmpMembers)-1-i] = v
		}
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid order")
	}

	total := int(memberCache.Len())

	return c.JSON(http.StatusOK, GetMembersResponse{
		Members: members,
		Total:   total,
	})
}

// 会員を取得
func getMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	member, ok := memberCache.Load(id)
	if ok {
		member.Read(func(m *Member) {
			ok = ok && !m.Banned
		})
	}
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	var mem Member
	member.Read(func(m *Member) {
		mem = *m
	})

	return c.JSON(http.StatusOK, mem)
}

type PatchMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員情報編集
func patchMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	var req PatchMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" && req.Address == "" && req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address or phoneNumber is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在を確認
	member, ok := memberCache.Load(id)
	if ok {
		member.Read(func(m *Member) {
			ok = ok && !m.Banned
		})
	}
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	query := "UPDATE `member` SET "
	params := []any{}
	if req.Name != "" {
		query += "`name` = ?, "
		params = append(params, req.Name)
	}
	if req.Address != "" {
		query += "`address` = ?, "
		params = append(params, req.Address)
	}
	if req.PhoneNumber != "" {
		query += "`phone_number` = ?, "
		params = append(params, req.PhoneNumber)
	}
	query = strings.TrimSuffix(query, ", ")
	query += " WHERE `id` = ?"
	params = append(params, id)

	_, err = tx.ExecContext(c.Request().Context(), query, params...)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	member.Write(func(member *Member) {
		if req.Name != "" {
			member.Name = req.Name
		}
		if req.Address != "" {
			member.Address = req.Address
		}
		if req.PhoneNumber != "" {
			member.PhoneNumber = req.PhoneNumber
		}
	})

	_ = tx.Commit()

	return c.NoContent(http.StatusNoContent)
}

// 会員をBAN
func banMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在を確認
	member, ok := memberCache.Load(id)
	if ok {
		member.Read(func(m *Member) {
			ok = ok && !m.Banned
		})
	}
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	_, err = tx.ExecContext(c.Request().Context(), "UPDATE `member` SET `banned` = true WHERE `id` = ?", id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, err = tx.ExecContext(c.Request().Context(), "DELETE FROM `lending` WHERE `member_id` = ?", id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	member.Write(func(member *Member) {
		member.Banned = true
	})
	memberCache.Forget(id)
	memberNameCache.Edit(func(members []*isulocker.Value[Member]) []*isulocker.Value[Member] {
		newMembers := make([]*isulocker.Value[Member], 0, len(members)-1)
		for _, member := range members {
			member.Read(func(m *Member) {
				if m.ID != id {
					newMembers = append(newMembers, member)
				}
			})
		}

		return newMembers
	})
	memberIDCache.Edit(func(members []*isulocker.Value[Member]) []*isulocker.Value[Member] {
		newMembers := make([]*isulocker.Value[Member], 0, len(members)-1)
		for _, member := range members {
			member.Read(func(m *Member) {
				if m.ID != id {
					newMembers = append(newMembers, member)
				}
			})
		}

		return newMembers
	})

	_ = tx.Commit()

	return c.NoContent(http.StatusNoContent)
}

// 会員証用のQRコードを取得
func getMemberQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	// 会員の存在確認
	member, ok := memberCache.Load(id)
	if ok {
		member.Read(func(m *Member) {
			ok = ok && !m.Banned
		})
	}
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	f, err := os.Open(filepath.Join(qrCodeDirName, fmt.Sprintf("%s.png", id)))
	if err == nil {
		defer f.Close()
		return c.Stream(http.StatusOK, "image/png", f)
	}

	pr, pw := io.Pipe()
	eg := errgroup.Group{}
	eg.Go(func() error {
		defer pw.Close()
		return generateQRCode(id, pw)
	})
	eg.Go(func() error {
		defer pr.Close()
		return c.Stream(http.StatusOK, "image/png", pr)
	})

	err = eg.Wait()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return nil
}

/*
---------------------------------------------------------------
Books API
---------------------------------------------------------------
*/

type PostBooksRequest struct {
	Title  string `json:"title"`
	Author string `json:"author"`
	Genre  Genre  `json:"genre"`
}

// 蔵書を登録 (複数札を一気に登録)
func postBooksHandler(c echo.Context) error {
	var reqSlice []PostBooksRequest
	if err := c.Bind(&reqSlice); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	res := []Book{}
	createdAt := time.Now()

	bi := query.NewBulkInsert("book", "`id`, `title`, `author`, `genre`, `created_at`", "(?, ?, ?, ?, ?)")
	for _, req := range reqSlice {
		if req.Title == "" || req.Author == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "title, author is required")
		}
		if req.Genre < 0 || req.Genre > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}

		var id string
		idPool.Write(func(idPool *[]string) {
			if len(*idPool) != 0 {
				id = (*idPool)[0]
				*idPool = (*idPool)[1:]
				poolLen.Dec()
			} else {
				id = generateID()
			}
		})

		bi.Add(id, req.Title, req.Author, req.Genre, createdAt)
		res = append(res, Book{
			ID:        id,
			Title:     req.Title,
			Author:    req.Author,
			Genre:     req.Genre,
			CreatedAt: createdAt,
		})
	}
	query, args := bi.Query()
	_, err := db.ExecContext(c.Request().Context(), query, args...)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	bookValues := make([]*isulocker.Value[GetBookResponse], 0, len(res))
	for _, book := range res {
		bookValue := isulocker.NewValue(GetBookResponse{
			Book:    book,
			Lending: false,
		}, "book")
		bookCache.Store(book.ID, bookValue)
		bookValues = append(bookValues, bookValue)
	}
	bookSliceCache.Edit(func(books []*isulocker.Value[GetBookResponse]) []*isulocker.Value[GetBookResponse] {
		books = append(books, bookValues...)
		sort.Slice(books, func(i, j int) bool {
			var ok bool
			books[i].Read(func(bookI *GetBookResponse) {
				books[j].Read(func(bookJ *GetBookResponse) {
					ok = bookI.Book.ID < bookJ.Book.ID
				})
			})

			return ok
		})

		return books
	})

	return c.JSON(http.StatusCreated, res)
}

const bookPageLimit = 50

type GetBooksResponse struct {
	Books []GetBookResponse `json:"books"`
	Total int               `json:"total"`
}

// 蔵書を検索
func getBooksHandler(c echo.Context) error {
	title := c.QueryParam("title")
	author := c.QueryParam("author")
	genre := c.QueryParam("genre")
	if genre != "" {
		genreInt, err := strconv.Atoi(genre)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if genreInt < 0 || genreInt > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}
	}
	if genre == "" && title == "" && author == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "title, author or genre is required")
	}

	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// 前ページの最後の蔵書ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_book_id")

	res := GetBooksResponse{
		Books: make([]GetBookResponse, 0, bookPageLimit),
		Total: 0,
	}
	bookSliceCache.Range(func(i int, book *isulocker.Value[GetBookResponse]) bool {
		book.Read(func(book *GetBookResponse) {
			if genre != "" {
				intGenre, err := strconv.Atoi(genre)
				if err != nil {
					log.Printf("failed to convert genre to int: %s\n", err)
					return
				}

				if book.Genre != Genre(intGenre) {
					return
				}
			}
			if title != "" {
				if !strings.Contains(book.Title, title) {
					return
				}
			}
			if author != "" {
				if !strings.Contains(book.Author, author) {
					return
				}
			}

			if res.Total >= (page-1)*bookPageLimit && len(res.Books) < bookPageLimit {
				res.Books = append(res.Books, *book)
			}
			res.Total++
		})

		return true
	})

	return c.JSON(http.StatusOK, res)
}

var (
	bookCache      = isucache.NewAtomicMap[string, *isulocker.Value[GetBookResponse]]("book")
	bookSliceCache = isucache.NewSlice("book_slice", make([]*isulocker.Value[GetBookResponse], 0, 20000), 20000)
)

func initBookCache() error {
	var books []GetBookResponse
	err := db.Select(&books, "SELECT  `book`.`id` AS `book.id`, `book`.`title` AS `book.title`, `book`.`author` AS `book.author`, `book`.`genre` AS `book.genre`, `book`.`created_at` AS `book.created_at`, "+
		"`lending`.`id` IS NOT NULL AS `is_lending` "+
		"FROM `book` LEFT OUTER JOIN `lending` ON `book`.`id` = `lending`.`book_id` ORDER BY book.id")
	if err != nil {
		return err
	}

	for _, book := range books {
		bookValue := isulocker.NewValue(book, "book")
		bookCache.Store(book.ID, bookValue)
		bookSliceCache.Append(bookValue)
	}

	return nil
}

type GetBookResponse struct {
	Book    `db:"book"`
	Lending bool `json:"lending" db:"is_lending"`
}

// 蔵書を取得
func getBookHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	bookValue, ok := bookCache.Load(id)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "no book found")
	}

	var res GetBookResponse
	bookValue.Read(func(v *GetBookResponse) {
		res = *v
	})

	return c.JSON(http.StatusOK, &res)
}

// 蔵書のQRコードを取得
func getBookQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	// 蔵書の存在確認
	_, ok := bookCache.Load(id)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "no book found")
	}

	f, err := os.Open(filepath.Join(qrCodeDirName, fmt.Sprintf("%s.png", id)))
	if err == nil {
		defer f.Close()
		return c.Stream(http.StatusOK, "image/png", f)
	}

	pr, pw := io.Pipe()
	eg := errgroup.Group{}
	eg.Go(func() error {
		defer pw.Close()
		return generateQRCode(id, pw)
	})
	eg.Go(func() error {
		defer pr.Close()
		return c.Stream(http.StatusOK, "image/png", pr)
	})

	err = eg.Wait()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return nil
}

/*
---------------------------------------------------------------
Lending API
---------------------------------------------------------------
*/

// 貸出期間(ミリ秒)
const LendingPeriod = 3000

type PostLendingsRequest struct {
	MemberID string   `json:"member_id"`
	BookIDs  []string `json:"book_ids"`
}

type PostLendingsResponse struct {
	Lending
	MemberName string `json:"member_name"`
	BookTitle  string `json:"book_title"`
}

// 本を貸し出し
func postLendingsHandler(c echo.Context) error {
	var req PostLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	// 会員の存在確認
	member, ok := memberCache.Load(req.MemberID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	lendingTime := time.Now()
	due := lendingTime.Add(LendingPeriod * time.Millisecond)
	res := make([]PostLendingsResponse, len(req.BookIDs))

	bi := query.NewBulkInsert("`lending`", "`id`, `book_id`, `member_id`, `due`, `created_at`", "(?, ?, ?, ?, ?)")
	bookValues := make([]*isulocker.Value[GetBookResponse], 0, len(req.BookIDs))
	for i, bookID := range req.BookIDs {
		// 蔵書の存在確認
		bookValue, ok := bookCache.Load(bookID)
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "book not found")
		}
		bookValues = append(bookValues, bookValue)

		// 貸し出し中かどうか確認
		var isLending bool
		bookValue.Read(func(v *GetBookResponse) {
			isLending = v.Lending
		})
		if isLending {
			return echo.NewHTTPError(http.StatusConflict, "this book is already lent")
		}

		id := generateID()

		bi.Add(id, bookID, req.MemberID, due, lendingTime)
		res[i] = PostLendingsResponse{
			Lending: Lending{
				ID:        id,
				BookID:    bookID,
				MemberID:  req.MemberID,
				Due:       due,
				CreatedAt: lendingTime,
			},
		}
		member.Read(func(member *Member) {
			res[i].MemberName = member.Name
		})
		bookValue.Read(func(book *GetBookResponse) {
			res[i].BookTitle = book.Title
		})
	}

	query, args := bi.Query()
	_, err := db.ExecContext(c.Request().Context(), query, args...)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	for _, bookValue := range bookValues {
		bookValue.Write(func(v *GetBookResponse) {
			v.Lending = true
		})
	}

	return c.JSON(http.StatusCreated, res)
}

type GetLendingsResponse struct {
	Lending
	MemberName string `json:"member_name"`
	BookTitle  string `json:"book_title"`
}

func getLendingsHandler(c echo.Context) error {
	overDue := c.QueryParam("over_due")
	if overDue != "" && overDue != "true" && overDue != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "over_due must be boolean value")
	}

	tx, err := db.BeginTxx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := "SELECT * FROM `lending`"
	args := []any{}
	if overDue == "true" {
		query += " WHERE `due` > ?"
		args = append(args, time.Now())
	}

	var lendings []Lending
	err = tx.SelectContext(c.Request().Context(), &lendings, query, args...)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	res := make([]GetLendingsResponse, len(lendings))
	for i, lending := range lendings {
		res[i].Lending = lending

		memberValue, ok := memberCache.Load(lending.MemberID)
		if !ok {
			member := Member{}
			err = tx.GetContext(c.Request().Context(), &member, "SELECT * FROM `member` WHERE `id` = ?", lending.MemberID)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}
			res[i].MemberName = member.Name
		} else {
			memberValue.Read(func(member *Member) {
				res[i].MemberName = member.Name
			})
		}

		bookValue, ok := bookCache.Load(lending.BookID)
		if !ok {
			return echo.NewHTTPError(http.StatusInternalServerError, "book not found")
		}
		bookValue.Read(func(book *GetBookResponse) {
			res[i].BookTitle = book.Title
		})
	}

	_ = tx.Commit()

	return c.JSON(http.StatusOK, res)
}

type ReturnLendingsRequest struct {
	MemberID string   `json:"member_id"`
	BookIDs  []string `json:"book_ids"`
}

// 蔵書を返却
func returnLendingsHandler(c echo.Context) error {
	var req ReturnLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在確認
	_, ok := memberCache.Load(req.MemberID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	bookValues := make([]*isulocker.Value[GetBookResponse], 0, len(req.BookIDs))
	for _, bookID := range req.BookIDs {
		bookValue, ok := bookCache.Load(bookID)
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "book not found")
		}
		var isLending bool
		bookValue.Read(func(book *GetBookResponse) {
			isLending = book.Lending
		})
		if !isLending {
			return echo.NewHTTPError(http.StatusNotFound, "book not lending")
		}
		bookValues = append(bookValues, bookValue)

		var lending Lending
		err = tx.GetContext(c.Request().Context(), &lending,
			"SELECT * FROM `lending` WHERE `member_id` = ? AND `book_id` = ?", req.MemberID, bookID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return echo.NewHTTPError(http.StatusNotFound, err.Error())
			}

			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		_, err = tx.ExecContext(c.Request().Context(),
			"DELETE FROM `lending` WHERE `member_id` =? AND `book_id` =?", req.MemberID, bookID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	for _, bookValue := range bookValues {
		bookValue.Write(func(v *GetBookResponse) {
			v.Lending = false
		})
	}

	_ = tx.Commit()

	return c.NoContent(http.StatusNoContent)
}
