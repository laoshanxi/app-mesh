#/usr/bin/env bash
# appc(1) completion                                     -*- shell-script -*-

_appc() {
    local cur prev words cword
    _init_completion || return

    case $prev in
    appc)
        COMPREPLY=($(compgen -W "logon logoff loginfo list add rm enable disable restart join cloud nodes run exec resource label config log get put passwd lock user" -- $cur))
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
