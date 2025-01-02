package grafana

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// https://grafana.com/grafana/plugins/grafana-simple-json-datasource/
type AppmeshGrafanaJson struct{}

// GrafanaQuery handles timeserie type queries.
func (AppmeshGrafanaJson) GrafanaQuery(ctx context.Context, target string, args QueryArguments) ([]DataPoint, error) {
	return []DataPoint{}, nil
}

func (AppmeshGrafanaJson) GrafanaQueryTable(ctx context.Context, target string, args TableQueryArguments) ([]TableColumn, error) {
	var authKey string
	// Access headers from context
	if header, ok := ctx.Value(requestHeadersKey).(http.Header); ok {
		authKey = header.Get("Authorization")
	}
	client := appmesh.NewHttpClient(appmesh.Option{Token: authKey})
	apps, err := client.ViewAllApps()

	result := make([]TableColumn, len(apps))
	for i := 0; i < len(apps); i++ {
		result[i] = TableColumn{}
	}

	var regTimes TableTimeColumn
	var appNames TableStringColumn
	var appOwner TableStringColumn
	var appStatus TableNumberColumn
	var appHealth TableNumberColumn
	var appPid TableNumberColumn
	var appMemory TableNumberColumn
	var appCpu TableNumberColumn
	var appReturn TableNumberColumn
	var appCmd TableStringColumn

	for i := range apps {
		meshApp := apps[i]
		t := time.Unix(*meshApp.RegisterTime, 0)
		regTimes = append(regTimes, t)
		appNames = append(appNames, meshApp.Name)
		if meshApp.Owner != nil {
			appOwner = append(appOwner, *meshApp.Owner)
		} else {
			appOwner = append(appOwner, "")
		}
		appStatus = append(appStatus, float64(meshApp.Status))
		appHealth = append(appHealth, float64(*meshApp.Health))
		if meshApp.Pid != nil {
			appPid = append(appPid, float64(*meshApp.Health))
		} else {
			appPid = append(appPid, 0)
		}
		if meshApp.Memory != nil {
			appMemory = append(appMemory, float64(*meshApp.Memory))
		} else {
			appMemory = append(appMemory, 0)
		}
		if meshApp.CPU != nil {
			appCpu = append(appCpu, float64(*meshApp.CPU))
		} else {
			appCpu = append(appCpu, 0)
		}
		if meshApp.ReturnCode != nil {
			appReturn = append(appReturn, float64(*meshApp.ReturnCode))
		} else {
			appReturn = append(appReturn, 0)
		}
		appCmd = append(appCmd, *meshApp.Command)

	}
	return []TableColumn{
		{Text: "register_time", Data: regTimes},
		{Text: "name", Data: appNames},
		{Text: "owner", Data: appOwner},
		{Text: "status", Data: appStatus},
		{Text: "pid", Data: appPid},
		{Text: "health", Data: appHealth},
		{Text: "memory", Data: appMemory},
		{Text: "cpu", Data: appCpu},
		{Text: "return", Data: appReturn},
		{Text: "command", Data: appCmd},
	}, err
}

func (AppmeshGrafanaJson) GrafanaAnnotations(ctx context.Context, query string, args AnnotationsArguments) ([]Annotation, error) {
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

func (AppmeshGrafanaJson) GrafanaSearch(ctx context.Context, target string) ([]string, error) {
	return []string{"example1", "example2", "example3"}, nil
}

func (AppmeshGrafanaJson) GrafanaAdhocFilterTags(ctx context.Context) ([]TagInfoer, error) {
	return []TagInfoer{
		TagStringKey("mykey"),
	}, nil
}

func (AppmeshGrafanaJson) GrafanaAdhocFilterTagValues(ctx context.Context, key string) ([]TagValuer, error) {
	return []TagValuer{
		TagStringValue("value1"),
		TagStringValue("value2"),
	}, nil
}

func RegGrafanaRestHandler(router *mux.Router) {
	// TODO: WithQuerier(AppmeshGrafanaJson{}) WithSearcher(AppmeshGrafanaJson{}) WithAnnotator(AppmeshGrafanaJson{})
	simJson := New(WithTableQuerier(AppmeshGrafanaJson{}))
	simJson.handleRestRouter(router)
}
