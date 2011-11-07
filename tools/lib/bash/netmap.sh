[ x"${KERNELTREE}" == x ] && {
    echo netmap.sh: KERNELTREE is not set: press enter to continue...
    read
}

NETMAPTREE=~/workspace/netmap/v2/netmap-v2

alias cdn='cd ${NETMAPTREE}'


function ninstall
{
    find ${NETMAPTREE}/sys | grep -v svn | \
    awk '{print length($0),$0}' | \
    sort -n | \
    awk '{print $2}' |\
    while read line; do
        filename=${KERNELTREE}/${line##${NETMAPTREE}/}

        if [ -d ${line} ]; then
            echoandexec mkdir -p ${filename}
        else
            echoandexec ln -s ${line} ${filename}
        fi
    done

    (
        echoandexec cd ${KERNELTREE}
        echoandexec patch -p0 < ${NETMAPTREE}/head-netmap.diff
    )
}

function nuninstall
{
    local line
    local filename

    (
        echoandexec cd ${KERNELTREE}
        echoandexec patch -p0 -R < ${NETMAPTREE}/head-netmap.diff
    )

    find ${NETMAPTREE}/sys | grep -v svn | \
    awk '{print length($0),$0}' | \
    sort -n -r | \
    awk '{print $2}' |\
    while read line; do
        filename=${KERNELTREE}/${line##${NETMAPTREE}/}

        if [ -d ${filename} ]; then
            echoandexec rmdir ${filename}
        else
            echoandexec rm ${filename}
        fi
    done

}

function ndiff
{
    (
        cd ${KERNELTREE}
        svn diff sys > "${NETMAPTREE}/head-netmap.diff"
        cd ${NETMAPTREE}
        svn diff
    )
}
