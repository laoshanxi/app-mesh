package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/mux"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"go.uber.org/zap"
)

// GrafanaHandler Is an opaque type that supports the required HTTP handlers for the
// Simple JSON plugin
type GrafanaHandler struct {
	query       Querier
	tableQuery  TableQuerier
	annotations Annotator
	search      Searcher
	tags        TagSearcher
}

type contextKey string

const requestHeadersKey contextKey = "requestHeaders"

var logger *zap.SugaredLogger = utils.GetLogger()

// New creates a new http.Handler that will answer to the required endpoint for
// a SimpleJSON source. You should use WithQuerier, WithTableQuerier,
// WithAnnotator and WithSearch to set handlers for each of the endpionts.
func New(opts ...Opt) *GrafanaHandler {
	Handler := &GrafanaHandler{}

	for _, o := range opts {
		if err := o(Handler); err != nil {
			panic(err)
		}
	}

	return Handler
}

func (h *GrafanaHandler) handleRestRouter(router *mux.Router) {
	router.HandleFunc("/appmesh_grafana", (h.HandleRoot)).Methods(http.MethodGet)
	router.HandleFunc("/appmesh_grafana/query", (h.HandleQuery)).Methods(http.MethodPost)
	router.HandleFunc("/appmesh_grafana/annotations", (h.HandleAnnotations)).Methods(http.MethodPost)
	router.HandleFunc("/appmesh_grafana/search", (h.HandleSearch)).Methods(http.MethodPost)
	router.HandleFunc("/appmesh_grafana/tag-keys", (h.HandleTagKeys)).Methods(http.MethodPost)
	router.HandleFunc("/appmesh_grafana/tag-values", (h.HandleTagValues)).Methods(http.MethodPost)

	// You can also add CORS for OPTIONS requests if needed:
	//router.HandleFunc("/appmesh_grafana", utils.Cors(utils.DefaultCORSConfig)(h.HandleOptions)).Methods(http.MethodOptions)
}

// WithSource will attempt to use the datasource provided as
// a Querier, TableQuerier, Annotator, Searcher and TagSearch
// if it supports the required interface.
func WithSource(src interface{}) Opt {
	return func(sjc *GrafanaHandler) error {
		if q, ok := src.(Querier); ok {
			sjc.query = q
		}
		if tq, ok := src.(TableQuerier); ok {
			sjc.tableQuery = tq
		}
		if a, ok := src.(Annotator); ok {
			sjc.annotations = a
		}
		if s, ok := src.(Searcher); ok {
			sjc.search = s
		}
		if ts, ok := src.(TagSearcher); ok {
			sjc.tags = ts
		}
		return nil
	}
}

// WithQuerier adds a timeserie query handler.
func WithQuerier(q Querier) Opt {
	return func(sjc *GrafanaHandler) error {
		sjc.query = q
		return nil
	}
}

// WithTableQuerier adds a table query handler.
func WithTableQuerier(q TableQuerier) Opt {
	return func(sjc *GrafanaHandler) error {
		sjc.tableQuery = q
		return nil
	}
}

// WithAnnotator adds an annoations handler.
func WithAnnotator(a Annotator) Opt {
	return func(sjc *GrafanaHandler) error {
		sjc.annotations = a
		return nil
	}
}

// WithSearcher adds a search handlers.
func WithSearcher(s Searcher) Opt {
	return func(sjc *GrafanaHandler) error {
		sjc.search = s
		return nil
	}
}

// WithTagSearcher adds adhoc filter tag  search handlers.
func WithTagSearcher(s TagSearcher) Opt {
	return func(sjc *GrafanaHandler) error {
		sjc.tags = s
		return nil
	}
}

// Opt provides configurable options for the Handler
type Opt func(*GrafanaHandler) error

// QueryCommonArguments describes the arguments common to timeserie and
// table queries.
type QueryCommonArguments struct {
	From, To time.Time
	Filters  []QueryAdhocFilter
}

// QueryArguments defines the options to a timeserie query.
type QueryArguments struct {
	QueryCommonArguments
	Interval time.Duration
	MaxDPs   int
}

// TableQueryArguments defines the options to a table query.
type TableQueryArguments struct {
	QueryCommonArguments
}

// A Querier responds to timeseri queries from Grafana
type Querier interface {
	GrafanaQuery(ctx context.Context, target string, args QueryArguments) ([]DataPoint, error)
}

// TagInfoer is an internal interface to describe difference types of tag.
type TagInfoer interface {
	tagName() string
	tagType() string
}

// TagStringKey represent an adhoc query string key.
type TagStringKey string

func (k TagStringKey) tagName() string {
	return string(k)
}

func (k TagStringKey) tagType() string {
	return "string"
}

// TagValuer is in an internal interface used to describe tag
// Values.
type TagValuer interface {
	tagValue() json.RawMessage
}

// TagStringValue represent an adhoc query string key.
type TagStringValue string

func (k TagStringValue) tagValue() json.RawMessage {
	// We igore the error here because the following should
	// always be marshable.
	bs, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{
		Text: string(k),
	})
	return json.RawMessage(bs)
}

// A TagSearcher allows the querying of tag keys and values for adhoc filters.
type TagSearcher interface {
	GrafanaAdhocFilterTags(ctx context.Context) ([]TagInfoer, error)
	GrafanaAdhocFilterTagValues(ctx context.Context, key string) ([]TagValuer, error)
}

// A TableQuerier responds to table queries from Grafana
type TableQuerier interface {
	GrafanaQueryTable(ctx context.Context, target string, args TableQueryArguments) ([]TableColumn, error)
}

// AnnotationsArguments defines the options to a annotations query.
type AnnotationsArguments struct {
	QueryCommonArguments
}

// An Annotator responds to queries for annotations from Grafana
type Annotator interface {
	GrafanaAnnotations(ctx context.Context, query string, args AnnotationsArguments) ([]Annotation, error)
}

// A Searcher responds to search queries from Grafana
type Searcher interface {
	GrafanaSearch(ctx context.Context, target string) ([]string, error)
}

// QueryAdhocFilter describes a user supplied filter to be added to
// each query target.
type QueryAdhocFilter struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// DataPoint represents a single datapoint at a given point in time.
type DataPoint struct {
	Time  time.Time
	Value float64
}

// A TableNumberColumn holds values for a "number" column in a table.
type TableNumberColumn []float64

func (TableNumberColumn) simpleJSONColumn() {
}

// A TableTimeColumn holds values for a "time" column in a table.
type TableTimeColumn []time.Time

func (TableTimeColumn) simpleJSONColumn() {
}

// A TableStringColumn holds values for a "string" column in a table.
type TableStringColumn []string

func (TableStringColumn) simpleJSONColumn() {
}

// TableColumnData is a private interface to this package, you should
// use one of TableStringColumn, TableNumberColumn, or TableTimeColumn
type TableColumnData interface {
	simpleJSONColumn()
}

// TableColumn represents a single table column. Data should
// be one the TableNumberColumn, TableStringColumn or TableTimeColumn types.
type TableColumn struct {
	Text string
	Data TableColumnData
}

// Annotation represents an annotation that can be displayed on a graph, or
// in a table.
type Annotation struct {
	Time    time.Time `json:"time"`
	TimeEnd time.Time `json:"timeEnd,omitempty"`
	Title   string    `json:"title"`
	Text    string    `json:"text"`
	Tags    []string  `json:"tags"`
}

// HandleRoot serves a plain 200 OK for /, required by Grafana
func (h *GrafanaHandler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	// Log the request
	logger.Debug("Requesting root for Grafana")

	// Set response headers
	w.Header().Set("Content-Type", "application/json") // Set content type to JSON
	w.WriteHeader(http.StatusOK)                       // Set status code to 200 OK

	// Write the response body
	responseBody := []byte("{\"message\": \"App Mesh Grafana SimpleJson data source\"}")
	if _, err := w.Write(responseBody); err != nil {
		logger.Errorf("Error writing response: %v", err)
	}
}

// simpleJSONTime is a wrapper for time.Time that reformats for
type simpleJSONTime time.Time

// MarshalJSON implements JSON marshalling
func (sjt *simpleJSONTime) MarshalJSON() ([]byte, error) {
	out := time.Time(*sjt).Format(time.RFC3339Nano)
	return json.Marshal(out)
}

// UnmarshalJSON implements JSON unmarshalling
func (sjt *simpleJSONTime) UnmarshalJSON(injs []byte) error {
	in := ""
	err := json.Unmarshal(injs, &in)
	if err != nil {
		return err
	}

	t, err := time.Parse(time.RFC3339Nano, in)
	if err != nil {
		return err
	}

	*sjt = simpleJSONTime(t)

	return nil
}

type simpleJSONDuration time.Duration

func (sjd *simpleJSONDuration) MarshalJSON() ([]byte, error) {
	out := time.Duration(*sjd).String()
	return json.Marshal(out)
}

func (sjd *simpleJSONDuration) UnmarshalJSON(injs []byte) error {
	in := ""
	err := json.Unmarshal(injs, &in)
	if err != nil {
		return err
	}

	d, err := time.ParseDuration(in)
	if err != nil {
		return err
	}

	*sjd = simpleJSONDuration(d)

	return nil
}

type simpleJSONRawRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type simpleJSONRange struct {
	From simpleJSONTime     `json:"from"`
	To   simpleJSONTime     `json:"to"`
	Raw  simpleJSONRawRange `json:"raw"`
}

type simpleJSONTarget struct {
	Target string `json:"target"`
	RefID  string `json:"refId"`
	Hide   *bool  `json:"hide"`
	Type   string `json:"type"`
}

/*
{
  "panelId": 1,
  "range": {
    "from": "2016-10-31T06:33:44.866Z",
    "to": "2016-10-31T12:33:44.866Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "rangeRaw": {
    "from": "now-6h",
    "to": "now"
  },
  "interval": "30s",
  "intervalMs": 30000,
  "targets": [
    { "target": "upper_50", refId: "A" , "hide": false. "type"; "timeserie"},
    { "target": "upper_75", refId: "B" }
  ],
  "format": "json",
  "maxDataPoints": 550
}
*/

type simpleJSONQuery struct {
	PanelID       int                `json:"panelId"`
	Range         simpleJSONRange    `json:"range"`
	RangeRaw      simpleJSONRawRange `json:"rangeRaw"`
	Interval      simpleJSONDuration `json:"interval"`
	IntervalMS    int                `json:"intervalMs"`
	Targets       []simpleJSONTarget `json:"targets"`
	Format        *string            `json:"format"`
	MaxDataPoints int                `json:"maxDataPoints"`
	AdhocFilters  []QueryAdhocFilter `json:"adhocFilters"`
}

/*
[
  {
    "target":"upper_75", // The field being queried for
    "datapoints":[
      [622,1450754160000],  // Metric value as a float , unixtimestamp in milliseconds
      [365,1450754220000]
    ]
  },
  {
    "target":"upper_90",
    "datapoints":[
      [861,1450754160000],
      [767,1450754220000]
    ]
  }
]
*/

type simpleJSONPTime time.Time

func (sjdpt *simpleJSONPTime) MarshalJSON() ([]byte, error) {
	out := time.Time(*sjdpt).UnixNano() / 1000000
	return json.Marshal(out)
}

func (sjdpt *simpleJSONPTime) UnmarshalJSON(injs []byte) error {
	in := int64(0)
	err := json.Unmarshal(injs, &in)
	if err != nil {
		return err
	}

	t := time.Unix(0, in*1000000)

	*sjdpt = simpleJSONPTime(t)

	return nil
}

type simpleJSONDataPoint struct {
	Value float64         `json:"value"`
	Time  simpleJSONPTime `json:"time"`
}

func (sjdp *simpleJSONDataPoint) MarshalJSON() ([]byte, error) {
	out := [2]float64{sjdp.Value, float64(time.Time(sjdp.Time).UnixNano() / 1000000)}
	return json.Marshal(out)
}

func (sjdp *simpleJSONDataPoint) UnmarshalJSON(injs []byte) error {
	in := [2]float64{}
	err := json.Unmarshal(injs, &in)
	if err != nil {
		return err
	}
	*sjdp = simpleJSONDataPoint{}
	sjdp.Value = in[0]
	sjdp.Time = simpleJSONPTime(time.Unix(0, int64(in[1])*1000000))

	return nil
}

type simpleJSONData struct {
	Target     string                `json:"target"`
	DataPoints []simpleJSONDataPoint `json:"datapoints"`
}

type simpleJSONTableColumn struct {
	Text string `json:"text"`
	Type string `json:"type"`
}

type simpleJSONTableRow []interface{}

type simpleJSONTableData struct {
	Type    string                  `json:"type"`
	Columns []simpleJSONTableColumn `json:"columns"`
	Rows    []simpleJSONTableRow    `json:"rows"`
}

func (h *GrafanaHandler) jsonTableQuery(ctx context.Context, req simpleJSONQuery, target simpleJSONTarget) (interface{}, error) {
	resp, err := h.tableQuery.GrafanaQueryTable(
		ctx,
		target.Target,
		TableQueryArguments{
			QueryCommonArguments: QueryCommonArguments{
				From:    time.Time(req.Range.From),
				To:      time.Time(req.Range.To),
				Filters: req.AdhocFilters,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	rowCount := 0
	var cols []simpleJSONTableColumn
	for _, cv := range resp {
		var colType string
		var dataLen int
		switch data := cv.Data.(type) {
		case TableNumberColumn:
			colType = "number"
			dataLen = len(data)
		case TableStringColumn:
			colType = "string"
			dataLen = len(data)
		case TableTimeColumn:
			colType = "time"
			dataLen = len(data)
		default:
			return nil, errors.New("invlalid column type")
		}

		if rowCount == 0 {
			rowCount = dataLen
		}
		if dataLen != rowCount {
			return nil, errors.New("all columns must be of equal length")
		}
		cols = append(cols, simpleJSONTableColumn{Text: cv.Text, Type: colType})
	}
	rows := make([]simpleJSONTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		rows[i] = make([]interface{}, len(resp))
	}

	for j := range resp {
		switch data := resp[j].Data.(type) {
		case TableNumberColumn:
			for i := 0; i < rowCount; i++ {
				rows[i][j] = data[i]
			}
		case TableStringColumn:
			for i := 0; i < rowCount; i++ {
				rows[i][j] = data[i]
			}
		case TableTimeColumn:
			for i := 0; i < rowCount; i++ {
				rows[i][j] = data[i]
			}
		}
	}

	return simpleJSONTableData{
		Type:    "table",
		Columns: cols,
		Rows:    rows,
	}, nil
}

func (h *GrafanaHandler) jsonQuery(ctx context.Context, req simpleJSONQuery, target simpleJSONTarget) (interface{}, error) {
	resp, err := h.query.GrafanaQuery(
		ctx,
		target.Target,
		QueryArguments{
			QueryCommonArguments: QueryCommonArguments{
				From:    time.Time(req.Range.From),
				To:      time.Time(req.Range.To),
				Filters: req.AdhocFilters,
			},
			Interval: time.Duration(req.Interval),
			MaxDPs:   req.MaxDataPoints,
		})
	if err != nil {
		return nil, err
	}

	sort.Slice(resp, func(i, j int) bool { return resp[i].Time.Before(resp[j].Time) })
	out := simpleJSONData{Target: target.Target}
	for _, v := range resp {
		out.DataPoints = append(out.DataPoints, simpleJSONDataPoint{
			Time:  simpleJSONPTime(v.Time),
			Value: v.Value,
		})
	}

	return out, nil
}

// HandleQuery hands the /query endpoint, calling the appropriate timeserie
// or table handler.
func (h *GrafanaHandler) HandleQuery(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Requesting")

	if h.query == nil && h.tableQuery == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	ctx := context.WithValue(r.Context(), requestHeadersKey, r.Header)

	req := simpleJSONQuery{}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	var out []interface{}
	for _, target := range req.Targets {
		var res interface{}
		switch target.Type {
		case "", "timeserie":
			if h.query == nil {
				http.Error(w, "timeserie query not implemented", http.StatusBadRequest)
				return
			}
			res, err = h.jsonQuery(ctx, req, target)
		case "table":
			if h.tableQuery == nil {
				http.Error(w, "table query not implemented", http.StatusBadRequest)
				return
			}
			res, err = h.jsonTableQuery(ctx, req, target)
		default:
			http.Error(w, "unknown query type, timeserie or table", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, res)
	}

	bs, err := json.Marshal(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(bs)
}

/*
{
  "range": {
    "from": "2016-04-15T13:44:39.070Z",
    "to": "2016-04-15T14:44:39.070Z"
  },
  "rangeRaw": {
    "from": "now-1h",
    "to": "now"
  },
  "annotation": {
    "name": "deploy",
    "datasource": "Simple JSON Datasource",
    "iconColor": "rgba(255, 96, 96, 1)",
    "enable": true,
    "query": "#deploy"
  }
}
*/

type simpleJSONAnnotation struct {
	Name      string `json:"name"`
	Query     string `json:"query"`
	Enable    bool   `json:"enable"`
	IconColor string `json:"iconColor"`
}

type simpleJSONAnnotationResponse struct {
	ReqAnnotation simpleJSONAnnotation `json:"annotation"`
	Time          simpleJSONPTime      `json:"time"`
	RegionID      int                  `json:"regionId,omitempty"`
	Title         string               `json:"title"`
	Text          string               `json:"text"`
	Tags          []string             `json:"tags"`
}

type simpleJSONAnnotationsQuery struct {
	Range      simpleJSONRange      `json:"range"`
	RangeRaw   simpleJSONRawRange   `json:"rangeRaw"`
	Annotation simpleJSONAnnotation `json:"annotation"`
}

// HandleAnnotations responds to the /annotation requests.
func (h *GrafanaHandler) HandleAnnotations(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Requesting")

	if h.annotations == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.Write([]byte("Allow: POST,OPTIONS"))
		return
	}

	req := simpleJSONAnnotationsQuery{}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := []simpleJSONAnnotationResponse{}
	anns, err := h.annotations.GrafanaAnnotations(
		ctx,
		req.Annotation.Query,
		AnnotationsArguments{
			QueryCommonArguments{
				From: time.Time(req.Range.From),
				To:   time.Time(req.Range.To),
			},
		})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	regionID := 1
	for i := range anns {
		startAnn := simpleJSONAnnotationResponse{
			ReqAnnotation: req.Annotation,
			Time:          simpleJSONPTime(anns[i].Time),
			Title:         anns[i].Title,
			Text:          anns[i].Text,
			Tags:          anns[i].Tags,
		}
		if !anns[i].TimeEnd.IsZero() {
			startAnn.RegionID = regionID
		}
		resp = append(resp, startAnn)

		if !anns[i].TimeEnd.IsZero() {
			endAnn := simpleJSONAnnotationResponse{
				ReqAnnotation: req.Annotation,
				Time:          simpleJSONPTime(anns[i].TimeEnd),
				Title:         anns[i].Title,
				Text:          anns[i].Text,
				Tags:          anns[i].Tags,
				RegionID:      regionID,
			}
			resp = append(resp, endAnn)
			regionID++
		}
	}

	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bs)
}

type simpleJSONSearchQuery struct {
	Target string
}

// HandleSearch implements the /search endpoint.
func (h *GrafanaHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Requesting")

	if h.search == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	req := simpleJSONSearchQuery{}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.search.GrafanaSearch(ctx, req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bs)
}

type simpleJSONQueryAdhocKey struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// HandleTagKeys implements the /tag-keys endpoint.
func (h *GrafanaHandler) HandleTagKeys(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Requesting")

	if h.tags == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	ctx := r.Context()

	tags, err := h.tags.GrafanaAdhocFilterTags(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var allTags []simpleJSONQueryAdhocKey
	for _, tag := range tags {
		allTags = append(allTags, simpleJSONQueryAdhocKey{
			Type: tag.tagType(),
			Text: tag.tagName(),
		})
	}

	bs, err := json.Marshal(allTags)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bs)
}

type simpleJSONTagValuesQuery struct {
	Key string `json:"key"`
}

// HandleTagValues implements the /tag-values endpoint.
func (h *GrafanaHandler) HandleTagValues(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Requesting")

	if h.tags == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	req := simpleJSONTagValuesQuery{}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vals, err := h.tags.GrafanaAdhocFilterTagValues(ctx, req.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var allVals []json.RawMessage
	for _, val := range vals {
		allVals = append(allVals, val.tagValue())
	}

	bs, err := json.Marshal(allVals)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bs)
}
