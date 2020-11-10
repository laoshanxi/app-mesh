package golang

import (
	"go_sdk/appmesh"
	"github.com/jbrodriguez/mlog"
	"os"
	"testing"
)

func init(){
		// log file size : 50Mb, log rotate number: 5
		fileSizeMb := 50
		rotateNumber := 5
		level := mlog.LevelInfo
		// https://github.com/jbrodriguez/mlog
		if os.Getenv("LOG_NO_FILE") == "true" {
			// Write to stdout/stderr only
			mlog.Start(mlog.LevelInfo, "")
		} else {
			mbNumber := fileSizeMb
			logPath := os.Args[0] + ".log"
			mlog.StartEx(level, logPath, mbNumber*1024*1024, rotateNumber)
			mlog.Info(logPath)
		}
}

func TestLogin(t *testing.T) {
	appMeshObj := appmesh.AppMesh{User:"admin",
	Pwd:"Admin123",
	Host:"10.1.241.225",
	Port:"6060",}
	appMeshObj.Login()
}

func TestGetResource(t *testing.T) {
	appMeshObj := appmesh.AppMesh{User:"admin",
	Pwd:"Admin123",
	Host:"10.1.241.225",
	Port:"6060",}
	appMeshObj.GetResource()
}

func TestRun(t *testing.T) {
	appMeshObj := appmesh.AppMesh{User:"admin",
	Pwd:"Admin123",
	Host:"10.1.241.225",
	Port:"6060",}
	appObj := appmesh.App{
		Command:"date",
		User:"root",
		WorkingDir:"/opt",
	}
	runTimeOut := 5
	appMeshObj.AppRun(&appObj,runTimeOut)
}