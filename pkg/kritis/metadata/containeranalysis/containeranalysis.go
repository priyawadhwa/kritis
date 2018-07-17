/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package containeranalysis

import (
	gen "cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	"encoding/json"
	"fmt"
	"github.com/grafeas/client-go/v1alpha1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"golang.org/x/net/context"
	googleAuth "golang.org/x/oauth2/google"
	"io/ioutil"
	"net/url"
	"strings"

	// "google.golang.org/api/iterator"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	"log"
)

const (
	PkgVulnerability = "PACKAGE_VULNERABILITY"
	PageSize         = int32(100)
)

// The ContainerAnalysis struct implements MetadataFetcher Interface.
type ContainerAnalysis struct {
	client *gen.Client
	ctx    context.Context
}

func NewContainerAnalysisClient() (*ContainerAnalysis, error) {
	ctx := context.Background()
	client, err := gen.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &ContainerAnalysis{
		client: client,
		ctx:    ctx,
	}, nil
}

// GetVulnerabilites gets Package Vulnerabilities Occurrences for a specified image.
// containerImage is fully qualified image url with "https://" prefix
func (c ContainerAnalysis) GetVulnerabilities(project string, containerImage string) ([]metadata.Vulnerability, error) {
	// vulnz := []metadata.Vulnerability{}
	// req := &containeranalysispb.ListOccurrencesRequest{
	// 	Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", containerImage, PkgVulnerability),
	// 	PageSize: PageSize,
	// 	Parent:   fmt.Sprintf("projects/%s", project),
	// }

	// it := c.client.ListOccurrences(c.ctx, req)
	// for {
	// 	occ, err := it.Next()
	// 	if err == iterator.Done {
	// 		break
	// 	}
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	log.Print(occ)
	// 	vulnz = append(vulnz, GetVulnerabilityFromOccurence(occ))
	// }
	occs, err := getOccurrences(containerImage)
	if err != nil {
		return nil, err
	}
	log.Printf("Found occs: %s", occs)
	vulnz := []metadata.Vulnerability{}
	for _, occ := range occs {
		vulnz = append(vulnz, getVulnz(occ))
	}
	return vulnz, nil
}

func getOccurrences(image string) ([]v1alpha1.Occurrence, error) {
	httpsImage := fmt.Sprintf("https://%s", image)
	filter := fmt.Sprintf("resourceUrl=\"%s\"", httpsImage)
	sp := strings.Split(strings.TrimPrefix(image, "https://"), "/")
	if len(sp) < 3 {
		return nil, fmt.Errorf("Malformed image %s should be gcr.io/<project>/<name>", image)
	}

	path := fmt.Sprintf("v1alpha1/projects/%s/occurrences", "priya-wadhwa")

	u := &url.URL{
		Scheme: "https",
		Host:   "containeranalysis.googleapis.com",
		Path:   path,
	}
	q := &url.Values{}
	q.Set("filter", filter)
	u.RawQuery = q.Encode()
	ctx := context.Background()
	authScope := "https://www.googleapis.com/auth/cloud-platform"
	c, err := googleAuth.DefaultClient(ctx, authScope)
	if err != nil {
		return nil, err
	}
	resp, err := c.Get(u.String())
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("%v", string(data))
		return nil, fmt.Errorf("non 200 status code: %d", resp.StatusCode)
	}

	oResp := v1alpha1.ListOccurrencesResponse{}
	if err := json.Unmarshal(data, &oResp); err != nil {
		return nil, err
	}

	return oResp.Occurrences, nil
}

func getVulnz(occ v1alpha1.Occurrence) metadata.Vulnerability {
	vulnDetails := occ.VulnerabilityDetails
	hasFixAvailable := isFixAvaliableV1(vulnDetails.PackageIssue)
	vulnerability := metadata.Vulnerability{
		Severity:        vulnDetails.Severity,
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.NoteName,
	}
	return vulnerability
}

func GetVulnerabilityFromOccurence(occ *containeranalysispb.Occurrence) metadata.Vulnerability {
	vulnDetails := occ.GetDetails().(*containeranalysispb.Occurrence_VulnerabilityDetails).VulnerabilityDetails
	hasFixAvailable := isFixAvaliable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        containeranalysispb.VulnerabilityType_Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return vulnerability
}

func isFixAvaliable(pis []*containeranalysispb.VulnerabilityType_PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation().GetVersion().Kind == containeranalysispb.VulnerabilityType_Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
}

func isFixAvaliableV1(pis []v1alpha1.PackageIssue) bool {
	for _, pi := range pis {
		if pi.FixedLocation.Version.Kind == "MAXIUM" {
			return false
		}
	}
	return true
}
