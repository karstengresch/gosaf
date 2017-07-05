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
	"net/url"
	"golang.org/x/net/publicsuffix"
	"log"
	"io/ioutil"
	"fmt"
	"os"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error{
	req.Header.Add("Authorization","Basic "+basicAuth("username1","password123"))
	return nil
}



func main() {
	var username string
	var password string
	var bookid string

	flag.StringVar(&username, "u", "USERNAME", "Your username.")
	flag.StringVar(&password, "p", "PASSWORD", "Your password.")
	flag.StringVar(&bookid, "b", "BOOKID", "The bookid. Open the book in the browser, you'll find it after the slash after the bookname.")

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Printf("  -u <username> -p <password> -i <bookid>, e.g. -u myUserName -p myPassword -i 87654321\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	fmt.Println("Input u: ", username)

	baseUrl := "https://www.safaribooksonline.com"

	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	client := http.Client{Jar: jar}
	resp, err := client.PostForm(baseUrl, url.Values{
		"password": {"loginpassword"},
		"username" : {"testuser"},
	})
	if err != nil {
		log.Fatal(err)
	}

	resp, err = client.PostForm("baseUrl"+"/oauth2/access_token/", url.Values{
		"userid": {"2"},
	})
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))   // print whole html of user profile data

	/*
	cookieJar, _ := cookiejar.New(nil)


	client := &http.Client{
		Jar: cookieJar,
		CheckRedirect: redirectPolicyFunc,
	}

	req, err := http.NewRequest("GET", "https://news.ycombinator.com/", nil)

	// TODO OAuth
	// TODO Follow https://github.com/nicohaenggi/SafariBooks-Downloader/blob/master/lib/safari/index.js but w/ multiple CSS.
	req.SetBasicAuth("username1", "password123")

*/

	/*

	i.e.

	form: {
      "client_id" : this.clientId,
      "client_secret" : this.clientSecret,
      "grant_type" : "password",
      "username" : username,
      "password" : password
    },



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
