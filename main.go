package main

import (
	"fmt"
	"log"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/jet/v2"
)

func main() {
	engine := jet.New(".", ".jet.html")
	
	// engine.Reload(true) // irrelevant
	
	// gofiber bug: no error even if the templates are invalid???
	err := engine.Load()
	if err != nil {
		panic(err)
	}

	server := fiber.New(fiber.Config{
		AppName:                 "PixivFE",
		DisableStartupMessage:   true,
		Views:                   engine,
		Prefork:                 false,
		JSONEncoder:             json.Marshal,
		JSONDecoder:             json.Unmarshal,
		ViewsLayout:             "layout",
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"0.0.0.0/0"},
		ProxyHeader:             fiber.HeaderXForwardedFor,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Println(err)

			// Status code defaults to 500
			code := fiber.StatusInternalServerError

			// // Retrieve the custom status code if it's a *fiber.Error
			// var e *fiber.Error
			// if errors.As(err, &e) {
			// 	code = e.Code
			// }

			// Send custom error page
			err = c.Status(code).Render("pages/error", fiber.Map{"Title": "Error", "Error": err})
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString(fmt.Sprintf("Internal Server Error: %s", err))
			}

			return nil
		},
	})

	server.Use(recover.New(recover.Config{EnableStackTrace: true}))

	// server.Use(compress.New(compress.Config{
	// 	Level: compress.LevelBestSpeed, // 1
	// }))

	// server.Use(limiter.New(limiter.Config{
	// 	Next:              CanRequestSkipLimiter,
	// 	Expiration:        30 * time.Second,
	// 	Max:               config.GlobalServerConfig.RequestLimit,
	// 	LimiterMiddleware: limiter.SlidingWindow{},
	// 	LimitReached: func(c *fiber.Ctx) error {
	// 		log.Println("Limit Reached!")
	// 		return errors.New("Woah! You are going too fast! I'll have to keep an eye on you.")
	// 	},
	// }))

	// // Global HTTP headers
	// server.Use(func(c *fiber.Ctx) error {
	// 	c.Set("X-Frame-Options", "SAMEORIGIN")
	// 	c.Set("X-Content-Type-Options", "nosniff")
	// 	c.Set("Referrer-Policy", "no-referrer")
	// 	c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	// 	c.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' %s; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; ", config.GetImageProxyOrigin(c)))
	// 	// use this if need iframe:  frame-ancestors 'self'

	// 	return c.Next()
	// })

	// server.Use(func(c *fiber.Ctx) error {
	// 	baseURL := c.BaseURL() + c.OriginalURL()
	// 	c.Bind(fiber.Map{"BaseURL": baseURL})
	// 	return c.Next()
	// })

	// server.Static("/favicon.ico", "./views/assets/favicon.ico")
	// server.Static("/robots.txt", "./views/assets/robots.txt")
	// server.Static("/assets/", "./views/assets")
	// server.Static("/css/", "./views/css")
	// server.Static("/js/", "./views/js")

	// Routes

	server.Get("/", IndexPage)
	// server.Get("/about", pages.AboutPage)
	// server.Get("/newest", pages.NewestPage)
	// server.Get("/discovery", pages.DiscoveryPage)
	// server.Get("/discovery/novel", pages.NovelDiscoveryPage)
	// server.Get("/ranking", pages.RankingPage)
	// server.Get("/rankingCalendar", pages.RankingCalendarPage)
	// server.Post("/rankingCalendar", pages.RankingCalendarPicker)
	// server.Get("/users/:id/:category?", pages.UserPage)
	// server.Get("/artworks/:id/", pages.ArtworkPage).Name("artworks")
	// server.Get("/artworks/:id/embed", pages.ArtworkEmbedPage)
	// server.Get("/artworks-multi/:ids/", pages.ArtworkMultiPage)
	// server.Get("/novel/:id/", pages.NovelPage)

	// // Settings group
	// settings := server.Group("/settings")
	// settings.Get("/", pages.SettingsPage)
	// settings.Post("/:type", pages.SettingsPost)

	// // Personal group
	// self := server.Group("/self")
	// self.Get("/", pages.LoginUserPage)
	// self.Get("/followingWorks", pages.FollowingWorksPage)
	// self.Get("/bookmarks", pages.LoginBookmarkPage)
	// self.Post("/addBookmark/:id", pages.AddBookmarkRoute)
	// self.Post("/deleteBookmark/:id", pages.DeleteBookmarkRoute)
	// self.Post("/like/:id", pages.LikeRoute)

	// server.Get("/tags/:name", pages.TagPage)
	// server.Post("/tags/:name", pages.TagPage)
	// server.Post("/tags",
	// 	func(c *fiber.Ctx) error {
	// 		name := c.FormValue("name")

	// 		return c.Redirect("/tags/"+name, http.StatusFound)
	// 	})

	// // Legacy illust URL
	// server.Get("/member_illust.php", func(c *fiber.Ctx) error {
	// 	return c.Redirect("/artworks/" + c.Query("illust_id"))
	// })

	// // Proxy routes
	// proxy := server.Group("/proxy")
	// proxy.Get("/i.pximg.net/*", pages.IPximgProxy)
	// proxy.Get("/s.pximg.net/*", pages.SPximgProxy)
	// proxy.Get("/ugoira.com/*", pages.UgoiraProxy)

	// // run sass when in development mode
	// if config.GlobalServerConfig.InDevelopment {
	// 	go func() {
	// 		cmd := exec.Command("sass", "--watch", "views/css")
	// 		cmd.Stdout = os.Stderr // heh. (sass quirk)
	// 		cmd.Stderr = os.Stderr
	// 		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGHUP}
	// 		runtime.LockOSThread() // O.O https://github.com/golang/go/issues/27505
	// 		err := cmd.Run()
	// 		if err != nil {
	// 			log.Println(fmt.Errorf("when running sass: %w", err))
	// 		}
	// 	}()
	// }

	// Listen
	addr := ":1234"
	log.Printf("PixivFE is running on http://%v/\n", addr)

	// note: string concatenation is very flaky
	err = server.Listen(addr)
	if err != nil {
		panic(err)
	}
}

func IndexPage(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{})
}
