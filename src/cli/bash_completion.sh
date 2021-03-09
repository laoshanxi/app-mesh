#/usr/bin/env bash
# appc(1) completion                                     -*- shell-script -*-

_appc() {
    local cur prev words cword
    _init_completion || return

    case $prev in
    appc)
        COMPREPLY=($(compgen -W "logon logoff loginfo view cloud resource label enable disable restart reg unreg run exec get put config passwd lock log" -- $cur))
        return
        ;;
    -n | --name)
        local APPS=$(appc view -l | awk 'NR>1 {print $2}')
        COMPREPLY=($(compgen -W "$APPS" -- $cur))
        return
        ;;
    -h | -v)
        return
        ;;
    esac

    _filedir
} && complete -F _appc appc

# ex: ts=4 sw=4 et filetype=sh
