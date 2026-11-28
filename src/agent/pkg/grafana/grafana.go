package grafana

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// https://grafana.com/grafana/plugins/grafana-simple-json-datasource/
type AppmeshGrafanaJSON struct{}

// GrafanaQuery handles timeserie type queries.
func (AppmeshGrafanaJSON) GrafanaQuery(ctx context.Context, target string, args QueryArguments) ([]DataPoint, error) {
	return []DataPoint{}, nil
}

func (AppmeshGrafanaJSON) GrafanaQueryTable(ctx context.Context, target string,
	args TableQueryArguments) ([]TableColumn, error) {
	var authKey string
	// Access headers from context
	if header, ok := ctx.Value(requestHeadersKey).(http.Header); ok {
		authKey = header.Get("Authorization")
	}
	client, err := appmesh.NewHTTPClient(appmesh.Option{})
	if err != nil {
		return nil, fmt.Errorf("create app mesh client: %w", err)
	}
	scheme, bearer, found := strings.Cut(strings.TrimSpace(authKey), " ")
	bearer = strings.TrimSpace(bearer)
	if !found || !strings.EqualFold(scheme, "Bearer") || bearer == "" {
		return nil, fmt.Errorf("bearer authorization is required")
	}
	client.SetToken(bearer)
	apps, err := client.ListApps()
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}

	var regTimes TableTimeColumn
	var appNames TableStringColumn
	var appOwner TableStringColumn
	var appEnabled TableNumberColumn
	var appHealth TableNumberColumn
	var appPid TableNumberColumn
	var appMemory TableNumberColumn
	var appCpu TableNumberColumn
	var appReturn TableNumberColumn
	var appCmd TableStringColumn

	for i := range apps {
		meshApp := apps[i]
		regTimes = append(regTimes, optTime(meshApp.RegisterTime))
		appNames = append(appNames, meshApp.Name)
		appOwner = append(appOwner, optString(meshApp.OwnerPrincipalID))
		appEnabled = append(appEnabled, optNumberFlag(meshApp.Enabled != nil && *meshApp.Enabled))
		appHealth = append(appHealth, optNumber(meshApp.Health))
		appPid = append(appPid, optNumber(meshApp.Pid))
		appMemory = append(appMemory, optNumber(meshApp.Memory))
		appCpu = append(appCpu, optNumber(meshApp.CPU))
		appReturn = append(appReturn, optNumber(meshApp.ReturnCode))
		appCmd = append(appCmd, optString(meshApp.Command))
	}
	return []TableColumn{
		{Text: "register_time", Data: regTimes},
		{Text: "name", Data: appNames},
		{Text: "owner", Data: appOwner},
		{Text: "enabled", Data: appEnabled},
		{Text: "pid", Data: appPid},
		{Text: "health", Data: appHealth},
		{Text: "memory", Data: appMemory},
		{Text: "cpu", Data: appCpu},
		{Text: "return", Data: appReturn},
		{Text: "command", Data: appCmd},
	}, err
}

// optTime dereferences an optional epoch-seconds field, defaulting to the zero time.
func optTime(v *int64) time.Time {
	if v != nil {
		return time.Unix(*v, 0)
	}
	return time.Time{}
}

// optString dereferences an optional string field, defaulting to "".
func optString(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}

// optNumber dereferences an optional numeric field, defaulting to 0.
func optNumber[T int | int64 | float64](v *T) float64 {
	if v != nil {
		return float64(*v)
	}
	return 0
}

// optNumberFlag maps a bool onto the numeric 0/1 column encoding.
func optNumberFlag(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func (AppmeshGrafanaJSON) GrafanaAnnotations(ctx context.Context, query string,
	args AnnotationsArguments) ([]Annotation, error) {
	return []Annotation{
		// A single point in time annotation
		{
			Time:  time.Unix(1234, 0),
			Title: "First Title",
			Text:  "First annotation",
		},
		// An annotation over a time range
		{
			Time:    time.Unix(1235, 0),
			TimeEnd: time.Unix(1237, 0),
			Title:   "Second Title",
			Text:    "Second annotation with range",
			Tags:    []string{"outage"},
		},
	}, nil
}

func (AppmeshGrafanaJSON) GrafanaSearch(ctx context.Context, target string) ([]string, error) {
	return []string{"example1", "example2", "example3"}, nil
}

func (AppmeshGrafanaJSON) GrafanaAdhocFilterTags(ctx context.Context) ([]TagInfoer, error) {
	return []TagInfoer{
		TagStringKey("mykey"),
	}, nil
}

func (AppmeshGrafanaJSON) GrafanaAdhocFilterTagValues(ctx context.Context, key string) ([]TagValuer, error) {
	return []TagValuer{
		TagStringValue("value1"),
		TagStringValue("value2"),
	}, nil
}

func RegisterGrafanaRESTHandler(router *mux.Router) {
	// TODO: WithQuerier(AppmeshGrafanaJSON{}) WithSearcher(AppmeshGrafanaJSON{}) WithAnnotator(AppmeshGrafanaJSON{})
	simJSON := New(WithTableQuerier(AppmeshGrafanaJSON{}))
	simJSON.handleRestRouter(router)
}
