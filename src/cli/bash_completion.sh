# appc completion                                     -*- shell-script -*-

if [[ $OSTYPE == *linux* ]]; then
    . "$BASH_SOURCE.linux"
    return
fi

# appc completion. This relies on the mount point being the third
# space-delimited field in the output of appc
#
_appc_modeule()
{
        local cur prev OPTS
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        case $cur in
                'appc')
                        COMPREPLY=( $(compgen -W "logon logoff view resource label enable disable restart reg unreg run get put config passwd lock log" -- $cur) )
                        return 0
                        ;;
        esac
        case $cur in
                '-n' | '--name')
                        local APPS=`appc view | awk '{print $2}'`
                        COMPREPLY=( $(compgen -W "$APPS" -- $cur) )
                        return 0
                        ;;
                '-h'|'-v')
                        return 0
                        ;;
        esac
        return 0
} && 
complete -F _appc_modeule appc

# ex: ts=4 sw=4 et filetype=sh