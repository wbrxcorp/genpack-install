# isozip ブランチでやること

genpack-install から ISO / ZIP 生成を切り出し、**root 権限不要の独立したツール**にする。

- `genpack-mkiso` — system image から起動可能な ISO9660 イメージを作る
- `genpack-mkzip` — system image とブートファイルを ZIP アーカイブにまとめる
- `genpack-install` — 実ディスクへのインストールと自己更新に専念（従来通り root 必須）

## 動機

1. **ISO を作るのに root が要らないようにする。** 現状 `--cdrom` / `--zip` は system image
   を loop mount するためだけに root を要求している。実際に読んでいるのは
   `.genpack/` のメタデータと `usr/lib/genpack-install/` のブートローダ数ファイルだけ。
2. **アーティファクトの肥大を止める。** `genpack/genpack-install` の RDEPEND に
   `dev-libs/libisoburn` があるため、ISO を作らないシステムにも xorriso + libisoburn(1.0MB)
   + libisofs(488KB) + libburn(322KB) が入っている。実測: インストーラアーティファクトの
   squashfs に `usr/bin/xorriso` と libisoburn 一式が present。
3. **外部コマンド依存をなくす。** unsquashfs も xorriso も呼ばずに済む（後述）。

## 決定事項

| 項目 | 決定 |
|---|---|
| 分割 | `genpack-install` / `genpack-mkiso` / `genpack-mkzip` の3バイナリ、同一パッケージ |
| genpack-install の `--cdrom` / `--zip` | **削除**。フォールバックメッセージも案内も不要（呼び出しているスクリプトは無い） |
| squashfs の読み方 | libsquashfs (`sys-fs/squashfs-tools-ng`)。`unsquashfs` の exec もループバックマウントもしない |
| ISO の作り方 | libisofs (`dev-libs/libisofs`) 直叩き。xorriso の exec はしない |
| `--add` オプション | `--add=DEST=SRC` 形式（例: `--add=system.ini=system.ini-for-thisvariant`）。複数指定可 |
| `--add` にディレクトリ/アーカイブ | **今回は無し**。必要になった時点できちんとした機能として追加する |
| `--additional-boot-files` | mkiso / mkzip には設けない。genpack-install の `--disk` 経路にある既存機能は残す |
| genpack-install への `--add` バックポート | **不要**。`--disk` 経路は `--system-cfg` / `--system-ini` のまま |
| 後方互換 | 気にしない。ドキュメント（`~/projects/genpack/docs/cli-install.md`）は更新する |

### `--add=DEST=SRC` の仕様

- `DEST` はイメージ内のパス、`SRC` はローカルファイル。**最初の `=` で分割する**
  （DEST は自分で決める名前なので `=` を含まない。SRC のローカルパスには `=` が入りうる）
- 省略形（`--add=file` のような `=` 無し）は認めない。常に `DEST=SRC` の形を要求する
- SRC は通常ファイルのみ。ディレクトリはエラーにする
- mkiso では ISO 内パス（`/system.cfg` 等）、mkzip では ZIP エントリ名になる
- DEST にサブディレクトリを含めてよい（中間ディレクトリは自動生成）
- DEST はパスを正規化してから重複判定する。正規化後に同じ DEST となる指定は警告を表示し、
  処理を継続して後勝ちとする
- `system.img` やブートファイルなど、ツールがあらかじめ配置するパスと重複した場合も警告を
  表示して後勝ちとする。必須ファイルを上書きして起動不能な成果物を作る可能性は利用者の
  責任とする
- 出力先と SRC が同じファイル（symlink / hardlink 経由を含む）になり、生成中の出力を
  `--add` で再び入力する循環が起きないよう、同一ファイル性を検査してエラーにする
- `--system-cfg` / `--system-ini` は mkiso / mkzip からは廃止し、`--add` に一本化する
  （`--add=system.cfg=./mycfg` と書く）

### 出力ファイルの扱い

- ISO / ZIP は出力先と同じディレクトリに一時ファイルとして生成する
- すべての入力を読み終え、ライブラリの close とストリームの終了を確認して完全な成果物に
  なってから、rename で指定された出力先へ置き換える
- 失敗時は一時ファイルを削除し、既存の出力ファイルには手を触れない
- 出力先が system image または `--add` の SRC と同じファイル（symlink / hardlink 経由を含む）
  なら、入力を破壊しないよう生成開始前にエラーにする

**注意（ドキュメントに書くこと）**: ISO に `system.cfg` を置いても、イメージ内に
`/boot/grub/grub.cfg` を持つアーティファクトでは読まれない。ブートローダの grub.cfg は
`loopback` 直後にイメージ内 grub.cfg があれば `configfile` で委譲してしまい、
`source ($BOOT_PARTITION)/system.cfg` はその後ろにあるため。

## ソース構成

現状 `genpack-install.cpp` 1ファイル 1104行。関数間の共有状態は `static bool debug` と
パス定数2つだけなので、分割はほぼ純粋な移動作業。

| ファイル | 中身 | リンク | 使うバイナリ |
|---|---|---|---|
| `common.cpp/hpp` | `debug`(extern化), `fork()`, `exec()`, `size_str()`, `get_freespace()`, `--add` パーサ | — | 全部 |
| `image.cpp/hpp` | `SystemImageReader`(libsquashfs), `check_system_image()`, `get_bootloader_path()` | `-lsquashfs` | 全部 |
| `iso.cpp/hpp` | `create_iso9660_image()`(libisofs) | `-lisofs` | mkiso |
| `zip.cpp/hpp` | `create_zip_archive()` + zip ヘルパ | `-lminizip` | mkzip |
| `genpack-install.cpp` | `TempMount`, `lsblk`, `install_*`, `format_*`, partitioning, main | `-lmount -lblkid` | genpack-install |
| `genpack-mkiso.cpp` | main のみ（argparse、60行程度） | — | — |
| `genpack-mkzip.cpp` | main のみ | — | — |

**`TempMount` は `genpack-install.cpp` に残す。** ただし system image の読み取りには使わず、
インストール先のブート / データパーティションをマウントする用途に限定する。system image は
genpack-install を含む3ツールすべてで `SystemImageReader` を通して読む。mkiso/mkzip からは
引き続き libmount/libblkid が完全に切れる。

### 結果の依存関係

| ツール | リンク | 実行時の外部コマンド |
|---|---|---|
| `genpack-mkiso` | `-lisofs -lsquashfs` | **なし** |
| `genpack-mkzip` | `-lsquashfs -lminizip` | **なし** |
| `genpack-install` | `-lmount -lblkid -lsquashfs` | parted, mkfs.vfat, mkfs.btrfs, mtools, grub-bios-setup, unzip |

## Makefile

オブジェクトファイル分割に変更する。

```make
COMMON_OBJS := common.o
IMAGE_OBJS  := image.o
CXXFLAGS ?= -std=c++23 -O2

%.o: %.cpp
	g++ $(CXXFLAGS) -c -o $@ $<

genpack-install.bin: genpack-install.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ -lmount -lblkid -lsquashfs

genpack-mkiso.bin: genpack-mkiso.o iso.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ -lisofs -lsquashfs

genpack-mkzip.bin: genpack-mkzip.o zip.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ -lminizip -lsquashfs
```

- `TARGETS` に `genpack-mkiso.bin` `genpack-mkzip.bin` を追加
- `install:` に `install -D -m 755 genpack-mkiso.bin $(DESTDIR)$(PREFIX)/bin/genpack-mkiso`
  （mkzip も同様）を追加
- ブートローダ生成ターゲット（`bootx64.efi` / `core.img` / `eltorito-*.img` 等）は変更なし
- `-lminizip` は genpack-install.bin から外れる

## ebuild（genpack-overlay 側、別リポジトリ）

`~/projects/genpack-overlay/genpack/genpack-install/` の ebuild を更新する。

```
IUSE="+install iso zip"
DEPEND="dev-cpp/argparse sys-boot/grub"
RDEPEND="
	install? ( sys-block/parted sys-fs/dosfstools sys-fs/mtools sys-fs/btrfs-progs
	           app-arch/unzip sys-boot/grub sys-fs/squashfs-tools-ng )
	iso?     ( dev-libs/libisofs sys-fs/squashfs-tools-ng )
	zip?     ( sys-libs/zlib[minizip] sys-fs/squashfs-tools-ng )
"
```

- `dev-libs/libisoburn` は不要になる（xorriso を呼ばない）
- アーティファクト側は `use: { "genpack/genpack-install": "-iso -zip" }` で
  ISO/ZIP ツールを外し、ビルドホスト側だけ有効にする運用
- Makefile 側も USE に応じてターゲットを出し分けられるようにしておく

## 調査で確定していること（再調査不要）

### libsquashfs で読める

`sys-fs/squashfs-tools-ng` 1.3.2 / `libsquashfs.so.1.4.1`、`pkg-config libsquashfs1` →
`-lsquashfs -lpthread`。ヘッダは `/usr/include/sqfs/`。

- xz 圧縮の system image を root なしで読める。open+メタ 14ms、32MB 抽出 104ms
- 抽出結果は unsquashfs と md5 一致
- **`sqfs_dir_reader_find_by_path()` はシンボリックリンクを追わない。** genpack の
  system image には `/lib -> usr/lib`、`/sbin -> usr/bin` があるので自前解決が必須。
  実装は `prototypes/sqfs_reader_proto.cpp` の `Image::lookup()`（40行程度）
- 存在確認は `SQFS_ERROR_NO_ENTRY(-13)` / `SQFS_ERROR_NOT_DIR(-12)` で判定できる

必要な読み取りは `.genpack/`(artifact, variant), `boot/kernel`, `boot/initramfs`,
`boot/bootcode.bin` の存在確認と、`usr/lib/genpack-install/` 配下の抽出だけ。
system image 本体は libisofs / minizip にパスで渡すのでコピーは発生しない。

### libisofs で xorriso と同等の ISO が作れる

`dev-libs/libisofs` 1.5.6、`pkg-config libisofs-1` → `-I/usr/include/libisofs -lisofs`。

`prototypes/mkiso_proto.cpp` で生成した 1.4GB の ISO が QEMU の BIOS / UEFI(OVMF) 双方で
`genpack-install login:` まで起動することを確認済み。`xorriso -indev -toc` の出力も一致。

呼ぶべき API とその引数は `prototypes/xorriso-libisofs-calls.log` に実測値がある
（LD_PRELOAD で xorriso が発行する libisofs 呼び出しを捕捉したもの）。要点:

- El Torito BIOS: `iso_image_set_boot_image(..., ELTORITO_NO_EMUL, "/boot/grub/i386-pc/boot.cat")`
  + `platform_id 0x00` + `el_torito_set_full_load(1)` + `isolinux_options bit0`(boot info table)
- El Torito EFI: `iso_image_add_boot_image("--interval:appended_partition_2:all::", ELTORITO_NO_EMUL)`
  + `platform_id 0xEF` + `el_torito_set_load_size(4)`。この `--interval:` 構文は
  **libisofs 自身が解釈する**（xorriso 固有ではない）
- appended partition: `iso_write_opts_set_partition_img(opts, 2, 0xef, path, 0)` +
  `appended_as_gpt(0)` + `part_like_isohybrid(0)` + `iso_mbr_part_type(-1)`
- write opts の非デフォルト値: iso_level 3 / omit_version_numbers 2 / allow_deep_paths 1 /
  allow_longer_paths 1 / no_force_dots 2 / relaxed_vol_atts 1 / always_gmt 1 /
  rrip_version_1_10 1 / dir_rec_mtime 7 / aaip_susp_1_10 1 / sort_files 1

**罠1**: `iso_image_create_burn_source()` が返す `struct burn_source` の定義を得るために
libburn.h を include してはいけない。C++ では `namespace burn { extern "C" {` で包まれるため
`burn::burn_source` が `::burn_source` と別型になる。libisofs.h 末尾(:9504〜)の
「libburn.h の写し」から転記して自前ヘッダに置く（`prototypes/mkiso_proto.cpp` 冒頭を参照）。

**罠2**: libisofs.h は `<stdint.h>` を include していない。C++ 側で `<cstdint>` を先に入れる。

**既知の差分**（実害なし、直さない）: xorriso 版はセッション開始が LBA 32
（上書き可能メディアのマルチセッション emulation 用）で、末尾に 300KB のパディングが付く。
libisofs 直叩きではどちらも付かず、ISO は約192セクタ小さくなる。BIOS/UEFI 起動には影響しない。

### 現行 `--cdrom` の既知のバグ

`create_iso9660_image()` は `ISO9660Options::system_config` を受け取っておきながら
xorriso コマンドラインに反映していない。つまり `--cdrom --system-cfg=...` は黙って無視される。
`--add` への一本化で解消する。

## 未決定事項

- **新ツールの引数の形。** `genpack-mkiso <out.iso> <system image>` の位置引数にするか、
  `genpack-mkiso --cdrom=<out.iso> <system image>` のように旧オプション名を残すか。
  位置引数の方が単機能ツールとして素直（`--label` と `--add` はオプションのまま）
- **system image 省略時の挙動。** 旧 `--cdrom` は省略時に
  `get_installed_system_image_path()`（稼働中システムのイメージ）を使っていた。
  ビルドホストで動かす mkiso にこの挙動が要るかは要検討。不要なら必須引数にして削除できる
- **Makefile の USE 連動。** ebuild の `iso` / `zip` USE に応じてターゲットを出し分ける方法
  （`make TOOLS="iso zip"` のような変数か、`install-iso` / `install-zip` の分割ターゲットか）

## 作業手順（推奨順）

1. `common.cpp/hpp` を切り出す（`debug` の extern 化が唯一の実質的変更）
2. `image.cpp/hpp` を新規に書く（`prototypes/sqfs_reader_proto.cpp` ベース）。
   `check_system_image()` / `get_bootloader_path()` と genpack-install の boot ファイル読み取りを
   Reader 越しに書き直す
3. `iso.cpp` を新規に書く（`prototypes/mkiso_proto.cpp` ベース）。
   エラー処理と `iso_image_unref` / `src->free_data` の解放をきちんと入れる
4. `zip.cpp` を切り出す。mkzip には `--additional-boot-files` を設けず、RasPi の `boot/`
   ツリー走査は Reader 経由に置き換える。ZIP64 は使わず、system image、各 `--add` の SRC、
   および入力ファイルの合計サイズが4GiB以上なら生成前にエラーにする
5. `genpack-mkiso.cpp` / `genpack-mkzip.cpp` の main を書く（`--add` パーサは common）
6. `genpack-install.cpp` から `--cdrom` / `--zip` を削除。
   `--disk` 用の `--additional-boot-files` は既存どおり残す
7. Makefile 更新
8. `~/projects/genpack/docs/cli-install.md` を書き直す（`introduction.md` の
   `--cdrom=<file>` の記述も要修正）
9. genpack-overlay の ebuild 更新（別リポジトリなので別コミット）
10. `prototypes/` を削除

## 検証手順

**「動いた」と言ってよいのは、実際に ISO を作って QEMU で BIOS / UEFI 両方から
起動させ、`genpack-install login:` が出るのを確認してから。**

テスト用のアーティファクトは `~/projects/genpack-artifacts/genpack-install/genpack-install-x86_64.squashfs`
（1.4GB, xz, baremetal プロファイル）。`.img` の方は FAT32 のディスクイメージなので
system image としては使えない点に注意。

```sh
# ISO 生成（root 不要。引数の形は未決定、下記「未決定事項」参照）
./genpack-mkiso.bin /tmp/test.iso \
    ~/projects/genpack-artifacts/genpack-install/genpack-install-x86_64.squashfs

# 構造確認
xorriso -indev /tmp/test.iso -toc
fdisk -l /tmp/test.iso

# BIOS 起動テスト（login: が出れば成功。timeout で終わるので exit 124 が正常）
timeout 150 qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 -cdrom /tmp/test.iso -boot d \
    -display none -serial file:/tmp/bios.log -no-reboot
tail -1 /tmp/bios.log

# UEFI 起動テスト
cp /usr/share/edk2-ovmf/OVMF_VARS.fd /tmp/vars.fd
timeout 150 qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2-ovmf/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/tmp/vars.fd \
    -cdrom /tmp/test.iso -boot d -display none -serial file:/tmp/uefi.log -no-reboot
tail -1 /tmp/uefi.log
```

正常系のログはこうなる（ISO の UUID は生成のたびに変わる）:

```
Command line: BOOT_IMAGE=/boot/kernel root=systemimg:2026-08-05-09-20-05-00 ...
dracut: Boot partition UUID=2026-08-05-09-20-05-00
dracut: Data partition not mounted.  Proceeding with tmpfs
genpack-install login:
```

未検証で確認が必要なもの:

- BIOS のみ / EFI のみの system image での分岐（`prototypes/mkiso_proto.cpp` に
  実装はあるがテストしていない）。EFI 単独時は `iso_image_set_boot_image()` に
  interval エントリを渡す形になる
- RasPi イメージ（`boot/bootcode.bin` を持つもの）での mkzip
- `--add` で置いたファイルが ISO / ZIP に正しく入ること

## 参考

- 検証コード一式は `prototypes/`（README あり）。本実装後に削除する
- インストーラアーティファクト側のリポジトリ: `~/projects/genpack-artifacts/genpack-install`
- ドキュメント: `~/projects/genpack/docs/cli-install.md`, `introduction.md`
- ebuild: `~/projects/genpack-overlay/genpack/genpack-install/`
