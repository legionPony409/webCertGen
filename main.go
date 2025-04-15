package main

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/legionPony409/webCertGen/certManager"
)

// handler обрабатывает как GET, так и POST запросы к корневому URL.
func checkCertHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/checkCert.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var inputText string
	if r.Method == http.MethodPost {
		// Получение данных из поля ввода
		inputText = r.FormValue("input")
	}

	outputBuffer := new(bytes.Buffer)
	if inputText != "" {
		certManager.CheckCertificate(strings.NewReader(inputText), outputBuffer)
	}

	data := map[string]interface{}{
		"Title":  "Простой веб-фронт на Go",
		"Body":   "Public certificate checker",
		"Input":  inputText,
		"Output": outputBuffer,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createCaCertHandler(w http.ResponseWriter, r *http.Request) {
	var certInfo certManager.CertificateInfo
	certInfo.CertOption = certManager.CaCert

	tmpl, err := template.ParseFiles("templates/createCaCert.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		// Получение данных из поля ввода
		certInfo.Org = r.FormValue("org")
		certInfo.Country = r.FormValue("country")
		certInfo.CommonName = r.FormValue("commonName")
	}

	outputBuffer := new(bytes.Buffer)
	if certInfo.Org != "" && certInfo.Country != "" && certInfo.CommonName != "" {
		certManager.CreateCertificate(&certInfo, outputBuffer)
	} else {
		outputBuffer.Write([]byte("Enter all fields!"))
	}

	data := map[string]interface{}{
		"Title":      "Простой веб-фронт на Go",
		"Body":       "CA certificate generator",
		"org":        certInfo.Org,
		"country":    certInfo.Country,
		"commonName": certInfo.CommonName,
		"Output":     outputBuffer,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createServerCertHandler(w http.ResponseWriter, r *http.Request) {
	var certInfo certManager.CertificateInfo
	certInfo.CertOption = certManager.CaCert

	outputBuffer := new(bytes.Buffer)

	tmpl, err := template.ParseFiles("templates/createServerCert.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var inputCaText, choice string
	if r.Method == http.MethodPost {
		// Получение данных из поля ввода
		inputCaText = r.FormValue("inputCA")
		choice = r.FormValue("choice")
		certInfo.Org = r.FormValue("org")
		certInfo.Country = r.FormValue("country")
		certInfo.CommonName = r.FormValue("commonName")

		switch choice {
		case "ServerCert":
			certInfo.CertOption = certManager.ServerCert
		case "KubeServiceCert":
			certInfo.CertOption = certManager.KubeServiceCert
			certInfo.KubeInfo.EnvName = r.FormValue("kubeEnv")
			certInfo.KubeInfo.ServiceName = r.FormValue("kubeServiceName")
			certInfo.KubeInfo.Namespace = r.FormValue("kubeNamespace")
		}

		certInfo.CaPublicCert, certInfo.CaPrivateCert = certManager.ExtractRawCertificate(strings.NewReader(inputCaText))

		if certInfo.Org != "" && certInfo.Country != "" && certInfo.CommonName != "" &&
			certInfo.CaPublicCert != nil && certInfo.CaPrivateCert != nil &&
			certInfo.CertOption != certManager.CaCert {
			certManager.CreateCertificate(&certInfo, outputBuffer)
		} else {
			outputBuffer.Write([]byte("Enter all fields!"))
		}
	}

	data := map[string]interface{}{
		"Title":           "Простой веб-фронт на Go",
		"Body":            "Server certificate generator",
		"caCertPair":      inputCaText,
		"choice":          choice,
		"kubeEnv":         certInfo.KubeInfo.EnvName,
		"kubeServiceName": certInfo.KubeInfo.ServiceName,
		"kubeNamespace":   certInfo.KubeInfo.Namespace,
		"org":             certInfo.Org,
		"country":         certInfo.Country,
		"commonName":      certInfo.CommonName,
		"Output":          outputBuffer,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func mainMenuHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "Сервер для сертификатов",
		"Body":  "Добро пожаловать в мой веб-сервер на Go!",
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	// Регистрируем обработчик для корневого URL
	http.HandleFunc("/", mainMenuHandler)
	http.HandleFunc("/checkCert", checkCertHandler)
	http.HandleFunc("/createCaCert", createCaCertHandler)
	http.HandleFunc("/createServerCert", createServerCertHandler)

	// Обслуживание статических файлов (например, CSS, JS, изображения)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Println("Сервер запущен на http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
