package main

import (
	"flag"
	"encoding/base64"
	_ "fmt"
	"net/http"
	"net/http/cookiejar"
	// "github.com/yhat/scrape"
	// "golang.org/x/net/html"
	// "golang.org/x/net/html/atom"
	"golang.org/x/crypto/ssh/terminal"
	"net/url"
	"golang.org/x/net/publicsuffix"
	"log"
	"io/ioutil"
	"fmt"
	"os"
)

type myjar struct {
	jar map[string] []*http.Cookie
}

func (p* myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	fmt.Printf("The URL is : %s\n", u.String())
	fmt.Printf("The cookie being set is : %s\n", cookies)
	p.jar [u.Host] = cookies
}

func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	fmt.Printf("The URL is : %s\n", u.String())
	fmt.Printf("Cookie being returned is : %s\n", p.jar[u.Host])
	return p.jar[u.Host]
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	req.Header.Add("Authorization", "Basic "+basicAuth("username1", "password123"))
	return nil
}

func main() {
	var username string
	var password string
	var bookurl string

	flag.StringVar(&username, "u", "", "Your username.")
	flag.StringVar(&password, "p", "", "Your password (optional, you can enter it interactively.)")
	flag.StringVar(&bookurl, "b", "", "The bookurl. Open the book in the browser, it ends /w a number.")

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Printf("  -u <username> -p <password> -i <bookurl>, e.g. -u myUserName -p myPassword -i 87654321\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	fmt.Println("Input u: ", username)

	if username == "" {
		fmt.Println("Username not given. Program exits.")
		return
	}

	if password == "" {
		fmt.Println("Please enter your password:")
		passwordHidden, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatal(err)
		}
		password = string(passwordHidden)
		// recheck
		if password == "" {
			fmt.Println("Password not given. Program exits.")
			return
		}
	}
	if bookurl == "" {
		fmt.Println("Book URL not given. You can find the bookurl using your web browser: https://www.safaribooksonline.com/library/view/yourbookname/9781788390552 \nProgram exits now.")
		return
	}

	// Connection creation



	/*
// TODO OAuth
// TODO Follow https://github.com/nicohaenggi/SafariBooks-Downloader/blob/master/lib/safari/index.js but w/ multiple CSS.

req.SetBasicAuth("username1", "password123")


i.e.

form: {
  "client_id" : this.clientId,
  "client_secret" : this.clientSecret,
  "grant_type" : "password",
  "username" : username,
  "password" : password
},

*/

	baseUrl := "https://www.safaribooksonline.com"
	// loginSubUrl := "/accounts/login"
	// accountDetailsAfterLoginUrl := https://www.safaribooksonline.com/api/v1/
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	// client := http.Client{Jar: jar}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: redirectPolicyFunc,
	}

	req, err := http.NewRequest("GET", baseUrl, nil)
	req.Header.Add("Authorization","Basic "+basicAuth(username,password))

	resp, err := client.Do(req)

	clientSecret := "f52b3e30b68c1820adb08609c799cb6da1c29975";
	clientId := "446a8a270214734f42a7";

	resp, err = client.PostForm(baseUrl, url.Values{

		"client_id":     {clientId},
		"client_secret": {clientSecret},
		"grant_type":    {"password"},
		"username":      {username},
		"password":      {password},
	})
	if err != nil {
		fmt.Println("Could not post form for client details.")
		log.Fatal(err)
	}

	resp, err = client.PostForm("baseUrl"+"/oauth2/access_token/", url.Values{
		"userid": {clientId},
	})
	if err != nil {
		fmt.Println("OAuth2 post form did not work.")
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data)) // print whole html of user profile data

	/*
	cookieJar, _ := cookiejar.New(nil)


	client := &http.Client{
		Jar: cookieJar,
		CheckRedirect: redirectPolicyFunc,
	}

	req, err := http.NewRequest("GET", "https://news.ycombinator.com/", nil)
*/

	/*

	if err != nil {
		panic(err)
	}

	// resp, err := client.Do(req)

	resp, err := http.PostForm("http://example.com/form",
		url.Values{"client_id": {"Value"},
					"id": {"123"}})

	root, err := html.Parse(resp.Body)
	if err != nil {
		panic(err)
	}

	// define a matcher
	matcher := func(n *html.Node) bool {
		// must check for nil values
		if n.DataAtom == atom.A && n.Parent != nil && n.Parent.Parent != nil {
			return scrape.Attr(n.Parent.Parent, "class") == "athing"
		}
		return false
	}
	// grab all articles and print them
	articles := scrape.FindAll(root, matcher)
	for i, article := range articles {
		fmt.Printf("%2d %s (%s)\n", i, scrape.Text(article), scrape.Attr(article, "href"))
	}
   */


}
