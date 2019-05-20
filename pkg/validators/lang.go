package validators

//constants
const (
	LangENG = "eng"
)

//IsValidLang checks if valid language
func IsValidLang(lang string) bool {
	return validLangs[lang]
}

//ListValidLangs returns valid languages
func ListValidLangs() []string {
	res := []string{}
	for k := range validLangs {
		res = append(res, k)
	}
	return res
}

var validLangs = map[string]bool{LangENG: true}
