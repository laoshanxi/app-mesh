"""dh_client.make_client 凭据选择测试：静态 token 优先，否则 SDK provider，均无则报错。"""

import os

import pytest

import dh_client
from appmesh import AppMeshClient, PasswordGrantProvider


def test_static_token_wins(tmp_path, monkeypatch):
	monkeypatch.setenv("APPMESH_BEARER_TOKEN", "t0")
	monkeypatch.setenv("DH_BOT_PASSWORD_FILE", str(tmp_path / "p"))  # 同时存在时静态优先
	c = dh_client.make_client()
	assert isinstance(c, AppMeshClient)
	assert c._token_provider is not None
	token = c._token_provider.get_access_token()
	assert token == "t0"


def test_provider_from_password_file(tmp_path, monkeypatch):
	pw = tmp_path / "dh-bot.password"
	pw.write_text("secret\n", encoding="utf-8")
	monkeypatch.delenv("APPMESH_BEARER_TOKEN", raising=False)
	monkeypatch.setenv("DH_BOT_PASSWORD_FILE", str(pw))
	monkeypatch.setenv("DH_BOT_USER", "dh-bot@demo.local")
	monkeypatch.setenv("DH_TOKEN_URL", "http://127.0.0.1:6062")
	c = dh_client.make_client()
	assert isinstance(c, AppMeshClient)
	assert isinstance(c._token_provider, PasswordGrantProvider)
	# 密码文件每次授予时重读：轮换免重启
	pw.write_text("rotated\n", encoding="utf-8")
	assert c._token_provider._read_password_file(str(pw)) == "rotated"


def test_missing_or_bad_credentials_raise(monkeypatch, tmp_path):
	monkeypatch.delenv("APPMESH_BEARER_TOKEN", raising=False)
	monkeypatch.setenv("DH_BOT_PASSWORD_FILE", str(tmp_path / "nope"))  # 文件不存在
	with pytest.raises(RuntimeError):
		dh_client.make_client()
	empty = tmp_path / "empty"
	empty.write_text("", encoding="utf-8")
	monkeypatch.setenv("DH_BOT_PASSWORD_FILE", str(empty))  # SDK 的 ValueError 统一转为 RuntimeError
	with pytest.raises(RuntimeError, match="凭据不可用"):
		dh_client.make_client()
	(tmp_path / "pw").write_text("secret", encoding="utf-8")
	monkeypatch.setenv("DH_BOT_PASSWORD_FILE", str(tmp_path / "pw"))
	monkeypatch.setenv("DH_TOKEN_URL", "http://10.0.0.5:6062")  # 非回环明文 URL 被 SDK 拒绝
	with pytest.raises(RuntimeError, match="凭据不可用"):
		dh_client.make_client()
	monkeypatch.delenv("DH_TOKEN_URL", raising=False)
	monkeypatch.delenv("DH_BOT_PASSWORD_FILE", raising=False)
	monkeypatch.setenv("DH_TEAM", "no-such-team")  # 隔离：不依赖本机 runtime 目录状态
	with pytest.raises(RuntimeError):  # 无任何凭据且约定路径为空
		dh_client.make_client()


def test_token_url_normalized(monkeypatch):
	monkeypatch.delenv("DH_TOKEN_URL", raising=False)
	assert dh_client._token_url() == "http://127.0.0.1:6062/auth/token"
	monkeypatch.setenv("DH_TOKEN_URL", "http://127.0.0.1:6062/")
	assert dh_client._token_url() == "http://127.0.0.1:6062/auth/token"
	monkeypatch.setenv("DH_TOKEN_URL", "http://10.0.0.5:6062/auth/token")
	assert dh_client._token_url() == "http://10.0.0.5:6062/auth/token"
