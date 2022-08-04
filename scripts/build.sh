#!/bin/sh

install_dependencies() {
	sudo apt update
	sudo apt install -y build-essential gawk flex bison openssl dkms \
		libelf-dev libudev-dev libpci-dev libiberty-dev autoconf \
		dwarves libncurses-dev libssl-dev
}

hide_git() {
	mkdir -p stash
	mv .git .gitattributes .gitignore stash/
}

generate_config() {
	make defconfig
	make syncconfig
	make archprepare
	./scripts/kconfig/merge_config.sh .config ./scripts/package/truenas/debian_amd64.config
	./scripts/kconfig/merge_config.sh .config ./scripts/package/truenas/truenas.config
	./scripts/kconfig/merge_config.sh .config ./scripts/package/truenas/debug.config
	./scripts/package/mkdebian
}

distclean() {
	cp .config stash/
	make distclean
	mv stash/.config .config
}

build_kernel() {
	make -j$(nproc) bindeb-pkg
}

prepare_artifacts() {
	mkdir -p artifacts
	mv ../*.deb ../*.changes ../*.buildinfo artifacts/
	cp .config artifacts/
}

unhide_git() {
	mv stash/.git stash/.gitattributes stash/.gitignore ./
	rmdir stash
}

usage() {
	echo "usage: ./scripts/build.sh [-ghik]"
	echo "	-g	only generate config"
	echo "	-h	help"
	echo "	-i	install dependencies"
	echo "	-k	only build kernel (no distclean)"
	exit 1
}

TEMP=$(getopt -o 'ghik' -n './scripts/build.sh' -- "$@")
if [ $? -ne 0 ]; then
	usage >&2
fi
eval set -- "$TEMP"
unset TEMP

while true; do
	case "$1" in
		'-g')
			opt_g=y
			shift
			continue
			;;
		'-h')
			usage
			;;
		'-i')
			opt_i=y
			shift
			continue
			;;
		'-k')
			opt_k=y
			shift
			continue
			;;
		'--')
			shift
			break
			;;
		*)
			echo 'Internal error!' >&2
			exit 1
			;;
	esac
done

[ $# -ne 0 ] && usage >&2

allopts="$opt_g$opt_i$opt_k"
[ "$allopts" = "yy" -o "$allopts" = "yyy" ] && usage >&2

if [ -n "$opt_i" ]; then
	install_dependencies
	exit
fi

hide_git
if [ -z "$opt_k" -o ! -e .config ]; then
       	generate_config
fi
if [ -n "$opt_g" ]; then
	unhide_git
	exit
fi
if [ -z "$opt_k" ]; then
	distclean
fi
build_kernel
prepare_artifacts
unhide_git
