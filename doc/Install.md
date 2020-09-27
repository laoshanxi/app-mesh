### Native installatin step

```text
# centos7
sudo yum install appmesh-1.8.4-1.x86_64.rpm
# ubuntu
sudo apt-get install appmesh_1.8.4_amd64.deb
# SUSE
sudo zypper install appmesh-1.8.4-1.x86_64.rpm
```
Note:
1. On windows WSL ubuntu, use `service appmesh start` to force service start, WSL VM does not have full init.d and systemd
2. Use env `export APPMESH_FRESH_INSTALL=Y` to enable fresh installation (otherwise, SSL and configuration file will not be refreshed)
3. The installation will create `appmesh` Linux user for default app running
4. On SUSE, use `sudo zypper install net-tools-deprecated` to install ifconfig tool before install App Mesh
