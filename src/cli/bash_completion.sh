# bash/zsh completion for appmesh CLI (appc) -*- shell-script -*-

_appc_global_flags="-H --host-url -F --forward-to -U --user -X --password -v --verbose -h --help -V --version"

_appc() {
    local cur prev words cword

    if declare -f _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        if [[ $COMP_CWORD -gt 0 ]]; then
            prev="${COMP_WORDS[COMP_CWORD-1]}"
        else
            prev=""
        fi
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local commands="logon logoff logout loginfo ls list view add reg rm remove unreg enable disable restart run exec shell get put label log config resource passwd mfa lock user appmgpwd appmginit"

    local flags_logon="--timeout --audience --show-token"
    local flags_loginfo="--show-token"
    local flags_add="--app --cmd --description --working-dir --status --shell --session-login --health-check --docker-image --pid --begin-time --end-time --daily-begin --daily-end --interval --cron --memory-limit --virtual-memory --cpu-shares --log-cache-size --permission --metadata --env --security-env --stop-timeout --exit --control --stdin --force"
    local flags_rm="--app --force"
    local flags_view="--long --show-output --pstree --app --log-index --follow --json"
    local flags_enable="--app --all"
    local flags_disable="--app --all"
    local flags_restart="--app --all"
    local flags_run="--app --cmd --description --working-dir --metadata --env --shell --session-login --lifetime --timeout"
    local flags_exec="--shell --session-login --lifetime --timeout --retry --env"
    local flags_shell="--session-login --lifetime --timeout --retry --env"
    local flags_get="--remote --local --no-attr"
    local flags_put="--remote --local --no-attr"
    local flags_label="--view --add --delete --label"
    local flags_log="--level"
    local flags_passwd="--target"
    local flags_lock="--target --lock"
    local flags_user="--json --all --force"
    local flags_mfa="--add --delete"

    case "${prev}" in
        --app)
            case "${words[1]}" in
                view|list|ls|rm|remove|unreg|enable|disable|restart|add|reg|run)
                    local apps
                    apps="$(appc ls 2>/dev/null | awk 'NR>1 {print $2}')"
                    COMPREPLY=( $(compgen -W "${apps}" -- "${cur}") )
                    ;;
            esac
            return ;;
        -L|--level)
            COMPREPLY=( $(compgen -W "DEBUG INFO NOTICE WARN ERROR" -- "${cur}") )
            return ;;
        -Q|--exit)
            COMPREPLY=( $(compgen -W "restart standby keepalive remove" -- "${cur}") )
            return ;;
        -r|--remote|-l|--local|--stdin|-m|--metadata|-j|--json)
            if declare -f _filedir >/dev/null 2>&1; then _filedir; else COMPREPLY=( $(compgen -f -- "${cur}") ); fi
            return ;;
        -H|--host-url|-F|--forward-to|-U|--user|-X|--password|-t|--timeout|-T|--lifetime|-a|--audience)
            return ;;
    esac

    if [[ ${cword} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return
    fi

    if [[ "${cur}" == -* ]]; then
        local subcmd="${words[1]}"
        local cmd_flags=""
        case "${subcmd}" in
            logon)                      cmd_flags="${flags_logon}" ;;
            loginfo)                    cmd_flags="${flags_loginfo}" ;;
            add|reg)                    cmd_flags="${flags_add}" ;;
            rm|remove|unreg)            cmd_flags="${flags_rm}" ;;
            view|list|ls)               cmd_flags="${flags_view}" ;;
            enable)                     cmd_flags="${flags_enable}" ;;
            disable)                    cmd_flags="${flags_disable}" ;;
            restart)                    cmd_flags="${flags_restart}" ;;
            run)                        cmd_flags="${flags_run}" ;;
            exec)                       cmd_flags="${flags_exec}" ;;
            shell)                      cmd_flags="${flags_shell}" ;;
            get)                        cmd_flags="${flags_get}" ;;
            put)                        cmd_flags="${flags_put}" ;;
            label)                      cmd_flags="${flags_label}" ;;
            log)                        cmd_flags="${flags_log}" ;;
            passwd)                     cmd_flags="${flags_passwd}" ;;
            lock)                       cmd_flags="${flags_lock}" ;;
            user)                       cmd_flags="${flags_user}" ;;
            mfa)                        cmd_flags="${flags_mfa}" ;;
        esac
        COMPREPLY=( $(compgen -W "${cmd_flags} ${_appc_global_flags}" -- "${cur}") )
        return
    fi

    case "${words[1]}" in
        get|put)
            if declare -f _filedir >/dev/null 2>&1; then _filedir; else COMPREPLY=( $(compgen -f -- "${cur}") ); fi
            ;;
    esac
}

# Shell-specific registration
if [[ -n "${ZSH_VERSION:-}" ]]; then
    if ! type bashcompinit >/dev/null 2>&1; then
        autoload -Uz bashcompinit && bashcompinit
    fi
    complete -F _appc appc
elif [[ -n "${BASH_VERSION:-}" ]]; then
    complete -F _appc appc
fi
