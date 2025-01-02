# bash completion for appmesh                            -*- shell-script -*-

_appc() {
    local cur prev words cword
    _init_completion || return

    case $prev in
    appc)
        COMPREPLY=($(compgen -W "logon logoff loginfo list add rm enable disable restart join cloud nodes run shell resource label config log get put passwd lock user" -- $cur))
        return
        ;;
    -a | --app)
        local APPS=$(appc ls -l | awk 'NR>1 {print $2}')
        COMPREPLY=($(compgen -W "$APPS" -- $cur))
        return
        ;;
    -h | -v)
        return
        ;;
    esac

    _filedir
} && complete -F _appc appc

# ex: filetype=sh
