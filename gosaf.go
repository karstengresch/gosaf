package main

import (
	"encoding/base64"
	_ "fmt"
	"net/http"
	"net/http/cookiejar"

	// "github.com/yhat/scrape"
	// "golang.org/x/net/html"
	// "golang.org/x/net/html/atom"
	// "github.com/spf13/cobra"
	"net/url"
	"golang.org/x/net/publicsuffix"
	"log"
	"io/ioutil"
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

	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	client := http.Client{Jar: jar}
	resp, err := client.PostForm("http://website.com/login", url.Values{
		"password": {"loginpassword"},
		"username" : {"testuser"},
	})
	if err != nil {
		log.Fatal(err)
	}


	resp, err = client.PostForm("http://website.com/upser_profile_page", url.Values{
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
