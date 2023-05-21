package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type Resultatjson struct {
	ResultsPerPage *int64  `json:"resultsPerPage,omitempty"`
	StartIndex     *int64  `json:"startIndex,omitempty"`
	TotalResults   *int64  `json:"totalResults,omitempty"`
	Result         *Result `json:"result,omitempty"`
}

type Result struct {
	CVEDataType      *DataType   `json:"CVE_data_type,omitempty"`
	CVEDataFormat    *DataFormat `json:"CVE_data_format,omitempty"`
	CVEDataVersion   *string     `json:"CVE_data_version,omitempty"`
	CVEDataTimestamp *string     `json:"CVE_data_timestamp,omitempty"`
	CVEItems         []CVEItem   `json:"CVE_Items,omitempty"`
}

type CVEItem struct {
	Cve              *CveClass       `json:"cve,omitempty"`
	Configurations   *Configurations `json:"configurations,omitempty"`
	Impact           *Impact         `json:"impact,omitempty"`
	PublishedDate    *string         `json:"publishedDate,omitempty"`
	LastModifiedDate *string         `json:"lastModifiedDate,omitempty"`
}

type Configurations struct {
	CVEDataVersion *string `json:"CVE_data_version,omitempty"`
	Nodes          []Node  `json:"nodes,omitempty"`
}

type Node struct {
	Operator *Operator     `json:"operator,omitempty"`
	Children []interface{} `json:"children,omitempty"`
	CpeMatch []CpeMatch    `json:"cpe_match,omitempty"`
}

type CpeMatch struct {
	Vulnerable            *bool         `json:"vulnerable,omitempty"`
	CpeName               []interface{} `json:"cpe_name,omitempty"`
	VersionStartIncluding *string       `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   *string       `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string       `json:"versionEndIncluding,omitempty"`
}

type CveClass struct {
	DataType    *DataType       `json:"data_type,omitempty"`
	DataFormat  *DataFormat     `json:"data_format,omitempty"`
	DataVersion *string         `json:"data_version,omitempty"`
	CVEDataMeta *CVEDataMeta    `json:"CVE_data_meta,omitempty"`
	Problemtype *Problemtype    `json:"problemtype,omitempty"`
	References  *References     `json:"references,omitempty"`
	Description *CveDescription `json:"description,omitempty"`
}

type CVEDataMeta struct {
	ID       *string   `json:"ID,omitempty"`
	Assigner *Assigner `json:"ASSIGNER,omitempty"`
}

type CveDescription struct {
	DescriptionData []DescriptionDatumElement `json:"description_data,omitempty"`
}

type DescriptionDatumElement struct {
	Lang  *Lang   `json:"lang,omitempty"`
	Value *string `json:"value,omitempty"`
}

type Problemtype struct {
	ProblemtypeData []ProblemtypeDatum `json:"problemtype_data,omitempty"`
}

type ProblemtypeDatum struct {
	Description []DescriptionDatumElement `json:"description,omitempty"`
}

type References struct {
	ReferenceData []ReferenceDatum `json:"reference_data,omitempty"`
}

type ReferenceDatum struct {
	URL       *string    `json:"url,omitempty"`
	Name      *string    `json:"name,omitempty"`
	Refsource *Refsource `json:"refsource,omitempty"`
	Tags      []Tag      `json:"tags,omitempty"`
}

type Impact struct {
	BaseMetricV3 *BaseMetricV3 `json:"baseMetricV3,omitempty"`
	BaseMetricV2 *BaseMetricV2 `json:"baseMetricV2,omitempty"`
}

type BaseMetricV2 struct {
	CvssV2                  *CvssV2  `json:"cvssV2,omitempty"`
	Severity                *Ity     `json:"severity,omitempty"`
	ExploitabilityScore     *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore             *float64 `json:"impactScore,omitempty"`
	ACInsufInfo             *bool    `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      *bool    `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     *bool    `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    *bool    `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired *bool    `json:"userInteractionRequired,omitempty"`
}

type CvssV2 struct {
	Version               *string         `json:"version,omitempty"`
	VectorString          *string         `json:"vectorString,omitempty"`
	AccessVector          *Vector         `json:"accessVector,omitempty"`
	AccessComplexity      *Ity            `json:"accessComplexity,omitempty"`
	Authentication        *Authentication `json:"authentication,omitempty"`
	ConfidentialityImpact *ItyImpact      `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       *ItyImpact      `json:"integrityImpact,omitempty"`
	AvailabilityImpact    *ItyImpact      `json:"availabilityImpact,omitempty"`
	BaseScore             *float64        `json:"baseScore,omitempty"`
}

type BaseMetricV3 struct {
	CvssV3              *CvssV3  `json:"cvssV3,omitempty"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}

type CvssV3 struct {
	Version               *string             `json:"version,omitempty"`
	VectorString          *string             `json:"vectorString,omitempty"`
	AttackVector          *Vector             `json:"attackVector,omitempty"`
	AttackComplexity      *Ity                `json:"attackComplexity,omitempty"`
	PrivilegesRequired    *AvailabilityImpact `json:"privilegesRequired,omitempty"`
	UserInteraction       *UserInteraction    `json:"userInteraction,omitempty"`
	Scope                 *Scope              `json:"scope,omitempty"`
	ConfidentialityImpact *AvailabilityImpact `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       *AvailabilityImpact `json:"integrityImpact,omitempty"`
	AvailabilityImpact    *AvailabilityImpact `json:"availabilityImpact,omitempty"`
	BaseScore             *float64            `json:"baseScore,omitempty"`
	BaseSeverity          *Ity                `json:"baseSeverity,omitempty"`
}

type DataFormat string

const (
	Mitre DataFormat = "MITRE"
)

type DataType string

const (
	Cve DataType = "CVE"
)

type Operator string

const (
	Or Operator = "OR"
)

type Assigner string

const (
	ContactWpscanCOM            Assigner = "contact@wpscan.com"
	CveMitreOrg                 Assigner = "cve@mitre.org"
	SecurityAdvisoriesGithubCOM Assigner = "security-advisories@github.com"
	VulturesJpcertOrJp          Assigner = "vultures@jpcert.or.jp"
)

type Lang string

const (
	En Lang = "en"
)

type Refsource string

const (
	Confirm Refsource = "CONFIRM"
	Debian  Refsource = "DEBIAN"
	Fedora  Refsource = "FEDORA"
	Misc    Refsource = "MISC"
	Mlist   Refsource = "MLIST"
)

type Tag string

const (
	Exploit            Tag = "Exploit"
	MailingList        Tag = "Mailing List"
	Mitigation         Tag = "Mitigation"
	Patch              Tag = "Patch"
	Product            Tag = "Product"
	ReleaseNotes       Tag = "Release Notes"
	ThirdPartyAdvisory Tag = "Third Party Advisory"
	VendorAdvisory     Tag = "Vendor Advisory"
)

type Ity string

const (
	Critical Ity = "CRITICAL"
	ItyHIGH  Ity = "HIGH"
	ItyLOW   Ity = "LOW"
	Medium   Ity = "MEDIUM"
)

type Vector string

const (
	AdjacentNetwork Vector = "ADJACENT_NETWORK"
	Network         Vector = "NETWORK"
)

type Authentication string

const (
	AuthenticationNONE Authentication = "NONE"
	Single             Authentication = "SINGLE"
)

type ItyImpact string

const (
	ItyImpactNONE ItyImpact = "NONE"
	Partial       ItyImpact = "PARTIAL"
)

type AvailabilityImpact string

const (
	AvailabilityImpactHIGH AvailabilityImpact = "HIGH"
	AvailabilityImpactLOW  AvailabilityImpact = "LOW"
	AvailabilityImpactNONE AvailabilityImpact = "NONE"
)

type Scope string

const (
	Changed   Scope = "CHANGED"
	Unchanged Scope = "UNCHANGED"
)

type UserInteraction string

const (
	Required            UserInteraction = "REQUIRED"
	UserInteractionNONE UserInteraction = "NONE"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Veuillez fournir une URL en argument.")
		return
	}

	url := os.Args[1]

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Erreur lors de la requête : %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Analyse les en-têtes de réponse pour obtenir des informations sur le serveur
	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")

	// Utilise goquery pour analyser le contenu HTML de la réponse
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Printf("Erreur lors de l'analyse du contenu HTML : %v\n", err)
		return
	}

	// Détermine le CMS et sa version
	cms, version := detectCMS(doc)

	if cms != "" {
		fmt.Printf("Le site est développé avec %s (version %s).\n", cms, version)
	} else {
		fmt.Println("Le CMS n'a pas pu être détecté.")
	}

	if server != "" {
		fmt.Printf("Le serveur utilise %s.\n", server)
	}

	if xPoweredBy != "" {
		fmt.Printf("Le serveur utilise %s.\n", xPoweredBy)
	}

	// Recherche des CVE associées au CMS et à sa version
	if cms != "" && version != "" {
		cveList := searchCVEs(cms, version)
		if len(cveList) > 0 {
			fmt.Printf("Les CVE suivantes sont associées à %s %s :\n", cms, version)
			for _, cveID := range cveList {
				fmt.Println(cveID)
			}
		} else {
			fmt.Println("Aucune CVE trouvée pour la combinaison CMS et version spécifiée.")
		}
	}
}

// Détermine le CMS et sa version
func detectCMS(doc *goquery.Document) (string, string) {
	if isWordPress(doc) {
		return "WordPress", getWordPressVersion(doc)
	}

	if isDrupal(doc) {
		return "Drupal", getDrupalVersion(doc)
	}

	if isJoomla(doc) {
		return "Joomla", getJoomlaVersion(doc)
	}

	// Ajoute ici la logique de détection pour d'autres CMS

	return "", ""
}

// Vérifie si le site est développé avec WordPress
func isWordPress(doc *goquery.Document) bool {
	return doc.Find("meta[name='generator'][content*='WordPress']").Length() > 0
}

// Récupère la version de WordPress
func getWordPressVersion(doc *goquery.Document) string {
	return doc.Find("meta[name='generator']").AttrOr("content", "")
}

// Vérifie si le site est développé avec Drupal
func isDrupal(doc *goquery.Document) bool {
	return doc.Find("meta[name='generator'][content*='Drupal']").Length() > 0
}

// Récupère la version de Drupal
func getDrupalVersion(doc *goquery.Document) string {
	return doc.Find("meta[name='generator']").AttrOr("content", "")
}

// Vérifie si le site est développé avec Joomla
func isJoomla(doc *goquery.Document) bool {
	return doc.Find("meta[name='generator'][content*='Joomla']").Length() > 0
}

// Récupère la version de Joomla
func getJoomlaVersion(doc *goquery.Document) string {
	return doc.Find("meta[name='generator']").AttrOr("content", "")
}

// Recherche des CVE associées au CMS et à sa version
func searchCVEs(cms, version string) []string {

	parts := strings.Split(version, " ")
	//cmss := strings.Join(parts[:len(parts)-1], " ")
	versionencoded := parts[len(parts)-1]
	cveURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:a:%s:%s:%s", cms, cms, versionencoded)

	resp, err := http.Get(cveURL)
	fmt.Println(cveURL)
	if err != nil {
		fmt.Printf("Erreur lors de la requête : %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var nvdResult Resultatjson
	err = json.NewDecoder(resp.Body).Decode(&nvdResult)

	if err != nil {
		fmt.Printf("Erreur lors du traitement de la réponse : %v\n", err)
		return nil
	}

	cveList := make([]string, 0)
	for _, item := range nvdResult.Result.CVEItems {
		cveID := *item.Cve.CVEDataMeta.ID
		cveList = append(cveList, cveID)
	}

	return cveList
}
