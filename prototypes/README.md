# prototypes/

`isozip` ブランチの作業用に、事前調査で書いた検証コードを置いてある。
**製品コードではない。本実装が終わったらこのディレクトリごと削除する。**

いずれも一般ユーザー権限で動く（root 不要）。

## sqfs_reader_proto.cpp

libsquashfs (sys-fs/squashfs-tools-ng) で system image を読む検証コード。
本実装の `image.cpp` / `SystemImageReader` の原型。

```sh
g++ -std=c++23 -O2 -o sqfs_reader_proto sqfs_reader_proto.cpp $(pkg-config --cflags --libs libsquashfs1)
./sqfs_reader_proto /path/to/artifact-x86_64.squashfs
```

確認済みの挙動:

- xz 圧縮の squashfs をマウントなしで読める（open + メタデータ 14ms、32MB 抽出 104ms）
- 抽出内容は `unsquashfs` の結果と md5 一致
- `sqfs_dir_reader_find_by_path()` は **シンボリックリンクを追わない**。
  `/lib -> usr/lib` があるイメージで `lib/genpack-install` は `SQFS_ERROR_NOT_DIR(-12)` になる。
  このファイルの `Image::lookup()` が1コンポーネントずつ辿って解決する実装
  （`/lib` 経由・`sbin/init` の2段リンクで動作確認済み）
- 存在しないパスは `SQFS_ERROR_NO_ENTRY(-13)`

## mkiso_proto.cpp

libisofs だけで ISO を生成する検証コード。本実装の `iso.cpp` の原型。

```sh
g++ -std=c++23 -O2 -o mkiso_proto mkiso_proto.cpp $(pkg-config --cflags --libs libisofs-1)
./mkiso_proto out.iso <bootloader dir> <system image .squashfs> GENPACK
```

`ldd` すると `libisofs.so.6` のみ。libisoburn も libburn もリンクしない。

確認済みの挙動:

- 生成した 1.4GB の ISO が QEMU の BIOS(SeaBIOS) / UEFI(OVMF) 双方で
  `genpack-install login:` まで起動する
- `xorriso -indev ... -toc` の出力は xorriso 版と一致
  （El Torito 2エントリ、boot.cat パス、boot_info_table=on、platform_id=0xEF、Rock Ridge + Joliet）
- MBR は p1=0x83(ISO領域) / p2=0xEF(FAT 63488 sectors) で xorriso 版と同じ構成

xorriso 版との差分は2点のみ。いずれも ISO ファイルとしての起動には無関係:

- xorriso はセッション開始を LBA 32 にする（上書き可能メディアのマルチセッション emulation 用）
- xorriso は末尾に 300KB のパディングを付ける（`xorriso/base_obj.c:262` のデフォルト）

### 本実装で判明した欠陥（このプロトタイプには残したまま）

**書き出しループが末尾を取りこぼす。** `burn_source->read_xt()` は残りデータが要求
サイズ未満だと **0 を返してその分を捨てる**。このファイルは常に 65536 バイトを要求
するので、最後の 1〜31 ブロック（最大 63KB）が失われる。

BIOS+EFI の ISO では失われるのが追記 EFI パーティション末尾のゼロ領域なので起動には
影響せず、上の「QEMU で起動する」は成立していた。しかし **EFI パーティションを持たない
BIOS 単独の ISO では `/system.img` の末尾が欠け、dracut が
`FATAL: Failed to mount RO layer` で停止する**。

本実装の `iso.cpp` は要求サイズを `get_size()` の残量で切り詰めることで回避している。

### 注意点

`struct burn_source` の定義を **自前で持っている**（ファイル冒頭）。
libburn.h は C++ では全体を `namespace burn { extern "C" { ... } }` で包む
（libburn.h:37-47）ため、`burn::burn_source` が libisofs.h の前方宣言する
`::burn_source` と別型になり使えない。libisofs.h の末尾(:9504〜)に
「libburn.h の写し」が置かれているのはこのためで、そこから転記してある。

また libisofs.h は `<stdint.h>` を include していないので、C++ 側で
`<cstdint>` を先に入れる必要がある。

## isotrace.c + xorriso-libisofs-calls.log

xorriso が libisofs をどう呼んでいるかを実測するための LD_PRELOAD shim と、
その出力。`mkiso_proto.cpp` のオプション値はすべてこのログから写した。

```sh
gcc -shared -fPIC -O1 -o isotrace.so isotrace.c -ldl
LD_PRELOAD=./isotrace.so xorriso -outdev out.iso ... -commit   # 旧実装と同じ引数で
cat /tmp/claude-1000/isotrace.log
```

ログ出力先はソース内にハードコードしてある（`/tmp/claude-1000/isotrace.log`）。
本実装後に「xorriso 版と同じ呼び出しになっているか」を再確認したくなったら使う。
