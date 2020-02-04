# appc(1) completion                                     -*- shell-script -*-

_appc()
{
    local cur prev words cword
    _init_completion || return

    case prev in
        appc)
            COMPREPLY=( $(compgen -W "logon logoff view resource label enable disable restart reg unreg run get put config passwd lock log" -- $cur) )
            return
            ;;
        -n|--name)
            local APPS=`appc view | awk '{print $2}'`
            COMPREPLY=( $(compgen -W "$APPS" -- $cur) )
            return
            ;;
        -h|-v)
            return
            ;;
    esac
} &&
complete -F _appc appc

# ex: ts=4 sw=4 et filetype=sh