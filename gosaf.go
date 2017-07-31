package main

import (
	"flag"
	_ "fmt"
	"net/http"
	"github.com/gorilla/schema"
	"golang.org/x/crypto/ssh/terminal"
	"net/url"
	"log"
	"encoding/json"
	"fmt"
	"os"
	"bytes"
)

type myjar struct {
	jar map[string][]*http.Cookie
}

type LoginFormData struct {
	ClientId     string            `schema:"client_id"`
	ClientSecret string            `schema:"client_secret"`
	Username     string            `schema:"username"`
	Password     string            `schema:"password"`
	GrantType    string            `schema:"grant_type"`
}

type BookRequestData struct {
	MethodType      string            `schema:"method"`
	headers         []string           `schema:"headers"`
	Uri        		string            `schema:"uri"`
	Json        	string            `schema:"json"`
}

func SafariAccessToken(baseUrl string, clientId string, clientSecret string, username string, password string, grantType string) (accessToken string, responseError error) {

	encoder := schema.NewEncoder()
	data := map[string]interface{}{}

	loginFormData := LoginFormData{clientId, clientSecret, username, password, grantType}
	form := url.Values{}
	err := encoder.Encode(loginFormData, form)

	if err != nil {
		fmt.Printf("Encode failed: " + err.Error())
	}

	// Use form values, for example, with an http client
	client := new(http.Client)
	response, err := client.PostForm(baseUrl, form)

	if response != nil {
		fmt.Printf("Status: " + string(response.Status))

		bodyBuffer := new(bytes.Buffer)
		bodyBuffer.ReadFrom(response.Body)
		bodyBufferString := bodyBuffer.String()

		fmt.Printf("Body: " + bodyBufferString)
		defer response.Body.Close()
		json.Unmarshal(bodyBuffer.Bytes(), &data)
		return data["access_token"].(string), responseError
	}

	return

}

func BookData(method string, accessToken string, uri string) (body string, responseError error) {
	encoder := schema.NewEncoder()
	data := map[string]interface{}{}
	headers := []string{"authorization", "Bearer " + accessToken}

	accessFormData := BookRequestData{"GET", headers, uri, "json"}
	form := url.Values{}
	encodeError := encoder.Encode(accessFormData, form)

	if encodeError != nil {
		fmt.Printf("Encode failed: " + encodeError.Error())
	}

	// Use form values, for example, with an http client
	client := new(http.Client)
	response, err := client.PostForm(uri, form)

	if response != nil {
		fmt.Printf("Status: " + string(response.Status))

		bodyBuffer := new(bytes.Buffer)
		bodyBuffer.ReadFrom(response.Body)
		bodyBufferString := bodyBuffer.String()

		fmt.Printf("Body: " + bodyBufferString)
		defer response.Body.Close()
		json.Unmarshal(bodyBuffer.Bytes(), &data)

		if err != nil {
			fmt.Printf("Status: " + string(response.Status))
		}

		return bodyBufferString, err
	}

	return

}

func checkRedirectFunc(req *http.Request, via []*http.Request) error {
	req.Header.Add("Authorization", via[0].Header.Get("Authorization"))
	return nil
}

func (p *myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	fmt.Printf("The URL is : %s\n", u.String())
	fmt.Printf("The cookie being set is : %s\n", cookies)
	p.jar [u.Host] = cookies
}

func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	fmt.Printf("The URL is : %s\n", u.String())
	fmt.Printf("Cookie being returned is : %s\n", p.jar[u.Host])
	return p.jar[u.Host]
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
		// TODO Follow https://github.com/nicohaenggi/SafariBooks-Downloader/blob/master/lib/safari/index.js but w/ multiple CSS.
	*/

	baseUrl := "https://www.safaribooksonline.com"
	clientSecret := "f52b3e30b68c1820adb08609c799cb6da1c29975";
	clientId := "446a8a270214734f42a7";
	// var accessToken string

	accessToken, err := SafariAccessToken(baseUrl+"/oauth2/access_token/", clientId, clientSecret, username, password, "password")
	if err != nil {
		fmt.Println("\nSafariHttpRequest failed.")
		log.Fatal(err)
	}
	fmt.Println("\nAccess Token is: " + accessToken)

	var bearer = "Bearer " + accessToken
	bookRequest, err := http.NewRequest("GET", bookurl, nil)
	bookRequest.Header.Add("authorization", bearer)
	client := &http.Client{}
	client.CheckRedirect = checkRedirectFunc

	bookResponse, err := client.Do(bookRequest)

	if err == nil {
		bodyBuffer := new(bytes.Buffer)
		bodyBuffer.ReadFrom(bookResponse.Body)
		bodyBufferString := bodyBuffer.String()

		fmt.Printf("Body: " + bodyBufferString)
	}
	defer bookResponse.Body.Close()
}
