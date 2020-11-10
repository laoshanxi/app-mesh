package appmesh

import (
	"encoding/base64"
	"github.com/jbrodriguez/mlog"
	"errors"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"strconv"
)

type AppMesh struct {
	User  string
	Pwd   string
	Host  string
	Port  string
	Token string
}

type App struct {
	Command    string
	User       string
	WorkingDir string
	Env        map[string]interface{}
}

var (
	appMeshUserBase64     string
	appMeshPasswordBase64 string
	appMeshRunTimeOut     = 5
	appMeshRetryNum       = 3
	appMeshRunUrl         = "https://%s:%s/appmesh/app/%s/run?timeout=%s"
	appMeshLoginUrl       = "https://%s:%s/appmesh/login"
	appMeshGetResourceUrl = "https://%s:%s/appmesh/resources"
	appMeshAppRunUrl      = "https://%s:%s/appmesh/app/syncrun?timeout=%s"
)

func (self *AppMesh) Login() (bool, error) {

	self.Token = ""
	appMeshUserBase64 = base64.StdEncoding.EncodeToString([]byte(self.User))
	appMeshPasswordBase64 = base64.StdEncoding.EncodeToString([]byte(self.Pwd))
	loginUrl := fmt.Sprintf(appMeshLoginUrl, self.Host, self.Port)
	headers := map[string]string{
		"username": appMeshUserBase64,
		"password": appMeshPasswordBase64}
	params := map[string]string{}
	body := map[string]interface{}{}
	response, err := Post(loginUrl, self.Token, body, params, headers, appMeshRunTimeOut)
	if err != nil {
		return false, err
	}
	// close the response finally
	defer response.Body.Close()
	if statusCode := response.StatusCode; statusCode != 200 {
		mlog.Warning("response faile status code:<%s>", response.Status)
		return false, err
	}
	res, _ := ioutil.ReadAll(response.Body)
	jsonObjPoint := new(map[string]interface{})
	json.Unmarshal(res, jsonObjPoint)
	self.Token = (*jsonObjPoint)["access_token"].(string)
	return true, nil
}

func (self *AppMesh) GetResource() (*map[string]interface{}, error) {

	GetResourceUrl := fmt.Sprintf(appMeshGetResourceUrl, self.Host, self.Port)
	for {
		if self.Token == "" {
			mlog.Trace("refresh Access Token")
			self.Login()
			appMeshRetryNum -= 1
		} else {
			break
		}
		if appMeshRetryNum < 1 {
			return nil, errors.New("GetResource get Access token fail")
		}
	}
	params := map[string]string{}
	headers := map[string]string{}
	response, err := Get(GetResourceUrl, self.Token, params, headers, appMeshRunTimeOut)
	mlog.IfError(err)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if statusCode := response.StatusCode; statusCode != 200 {
		mlog.Warning("response faile status code:<%s>", response.Status)
		return nil, err
	}
	res, _ := ioutil.ReadAll(response.Body)
	jsonObjPoint := new(map[string]interface{})
	err = json.Unmarshal(res, jsonObjPoint)
	return jsonObjPoint, nil
}

func (self *AppMesh) AppRun(app *App, RunTimeOut int) (bool, string, int, error) {

	// run app acording to the app information
	/**
	return
	bool: if this app run successful
	string: this app run output result
	int: this app run exit code -888 is mean error when respone the server
	error: this app run error information
	 **/

	for {
		if self.Token == "" {
			mlog.Trace("refresh Access Token")
			self.Login()
			appMeshRetryNum -= 1
		} else {
			appMeshRetryNum = 3
			break
		}
		if appMeshRetryNum < 1 {
			appMeshRetryNum = 3
			return false, "", -888, errors.New("GetResource get Access token fail")
		}
	}
	if RunTimeOut < 5 {
		RunTimeOut = appMeshRunTimeOut
	}
	AppRunUrl := fmt.Sprintf(appMeshAppRunUrl, self.Host, self.Port, RunTimeOut)
	body := map[string]interface{}{
		"command":     app.Command,
		"user":        app.User,
		"working_dir": app.WorkingDir,
		"env":         app.Env}
	params := map[string]string{}
	headers := map[string]string{}
	respone, err := Post(AppRunUrl, self.Token, body, params, headers, RunTimeOut)
	mlog.IfError(err)
	if err != nil {
		return false, "", -1, err
	}
	defer respone.Body.Close()
	if statusCode := respone.StatusCode; statusCode != 200 {
		mlog.Warning("response faile status code:<%s>", respone.Status)
		return false, "", -888, err
	}
	res, _ := ioutil.ReadAll(respone.Body)
	exitCode, _ := strconv.Atoi(respone.Header["Exit_code"][0])
	return true, string(res), exitCode, nil
}
