# Customize application start behavior

App Mesh can be used as a daemon application used to monitor and launch other applications on Linux, it is most like crontab and supervisor but much simple and powerful.
For application deployment, application startup behavior can be managed by App Mesh on local host to get High Available benefit.

## Solution

App Mesh support monitor both long-running and short-running applications, for more details, refer to [Command Line](https://app-mesh.readthedocs.io/en/latest/CLI.html)

## Register an existing application to App Mesh

By default, you can register your application simply by specify start command:

```shell
appc add -n myapp--perm 11  -c 'sh /root/data/deploy/myapp.sh'
```

### Integrate to application installation script

If your application package was pack yourself, you can add the startup behavior to post-installation script, with this, your app will be monitored and started automatically without any missing.

```shell
appc add -n mysql--perm 11  -c 'mysqld'
```
