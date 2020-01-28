# appc(1) completion                                     -*- shell-script -*-

_appc_modeule()
{
    local cur prev words cword
    _init_completion || return
    
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    case $cur in
        appc)
            COMPREPLY=( $(compgen -W "logon logoff view resource label enable disable restart reg unreg run get put config passwd lock log" -- $cur) )
            return 0
            ;;
        -n|--name)
            local APPS=`appc view | awk '{print $2}'`
            COMPREPLY=( $(compgen -W "$APPS" -- $cur) )
            return 0
            ;;
        -h|-v)
            return 0
            ;;
    esac
    return 0
} &&
complete -F _appc_modeule appc

# ex: ts=4 sw=4 et filetype=sh