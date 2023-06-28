# raw ebpf

## pinning

bpf的所有内核对象都可以通过pin的方法对所有bpf程序, 包括内核态和用户态程序可见, 这些对象中常用的是program和map. 

bpf在内核中管理对象的方式是为对象在内存中划出一片空间, 然后使用一个匿名inode指向这片空间, 这个inode有一个fd(文件描述符)指向它, 但fd本质上作为一个C变量, 最大的可见范围也只能达到整个程序, 将这个匿名inode挂载到bpffs上为其他bpf程序提供了访问内核对象的方法.

bpf提供了接口来将对象pin到bpffs中, 和获取特定路径上所pin的对象的函数

```C
int bpf_obj_pin(int fd, const char *pathname)

int bpf_obj_get(const char *pathname)
```

其底层实现都直接依赖于syscall

## map的读写(使用helpers)

在获取map fd后就可以调用helper读写map, 用户端和内核端调用方法略有区别, 但效果相同. 

查找map:

```C
内核端 static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

用户端 int bpf_map_lookup_elem(int fd, const void *key, void *value)
```

内核端返回值为value指针, 用户端则将key放在参数所给的指针中, 返回值表示成功与否.

更新map:

```C
内核端 static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
用户端 int bpf_map_update_elem(int fd, const void *key, const void *value,	__u64 flags)
```

返回值为0表示成功, 否则返回负数错误值.

flags参数有三种选择. BPF_NOEXIST: 更新使用的key*必须不*出现在map中, BPF_EXIST: 更新使用的key*必须*存在于map中, BPF_ANY: 任意情况. 注意BPF_NOEXIST不能在BPF_MAP_TYPE_ARRAY或BPF_MAP_TYPE_PERCPU_ARRAY中使用, 因为对这两种map来说所有key都存在, 如果使用会返回错误.


删除map元素:

```C
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
用户端 int bpf_map_delete_elem(int fd, const void *key)
```

用户端和内核端读写map的区别在于:
- 用户端总是用map fd指定要读写的map, 内核端使用指向map对象的指针
- 用户端函数的功能是通过系统调用实现(在libbpf中观察的结果, 有待进一步研究), 内核端的调用实际上是调用了一个函数指针, 在内核源码中发现了读写函数的不同实现, 推测是一种(函数级别的)多态策略, 在编译或执行时确定实际调用的函数.
- 得到结果的形式不同, 如lookup_elem

**map-in-map**

map有一种特殊的用法, 令一个map的value保存其他map的id, 这又可以称为map-in-map, 包括两种类型BPF_MAP_TYPE_ARRAY_OF_MAPS和BPF_MAP_TYPE_HASH_OF_MAPS, 相较于一般map有以下特点

- 外层map只能在用户端程序中进行写入, BPF程序仅有读权限
- 外层map的value是内层map的id, 而不是fd, 可以通过调用libbpf相关API进行转换, BPF程序不需转换

> 注: 内核现仅支持一层嵌套, 不允许多层, 见[Kernel文档](https://docs.kernel.org/bpf/map_of_maps.html)

给出几个片段展示其用法

```C
int create_outer_array(int inner_fd) {
        LIBBPF_OPTS(bpf_map_create_opts, opts, .inner_map_fd = inner_fd);
        int fd;

        fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS,
                            "example_array",       /* name */
                            sizeof(__u32),         /* key size */
                            sizeof(__u32),         /* value size */
                            256,                   /* max entries */
                            &opts);                /* create opts */
        return fd;
}
```

```C
int add_devmap(int outer_fd, int index, const char *name) {
        int fd;

        fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP, name,
                            sizeof(__u32), sizeof(__u32), 256, NULL);
        if (fd < 0)
                return fd;

        return bpf_map_update_elem(outer_fd, &index, &fd, BPF_ANY);
}
```

```C
struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} inner_map1 SEC(".maps"),
  inner_map2 SEC(".maps");

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
	/* it's possible to use anonymous struct as inner map definition here */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		/* changing max_entries to 2 will fail during load
		 * due to incompatibility with inner_map definition */
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} outer_arr SEC(".maps") = {
	/* (void *) cast is necessary because we didn't use `struct inner_map`
	 * in __inner(values, ...)
	 * Actually, a conscious effort is required to screw up initialization
	 * of inner map slots, which is a great thing!
	 */
	.values = { (void *)&inner_map1, 0, (void *)&inner_map2 },
};

...

SEC("raw_tp/sys_enter")
int handle__sys_enter(void *ctx)
{
	struct inner_map *inner_map;
	int key = 0, val;

	inner_map = bpf_map_lookup_elem(&outer_arr, &key);
	if (!inner_map)
		return 1;
	val = input;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	inner_map = bpf_map_lookup_elem(&outer_hash, &key);
	if (!inner_map)
		return 1;
	val = input + 1;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	inner_map = bpf_map_lookup_elem(&outer_arr_dyn, &key);
	if (!inner_map)
		return 1;
	val = input + 2;
	bpf_map_update_elem(inner_map, &key, &val, 0);

	return 0;
}
```

# libbpf

## compiling



## loading & attaching

内核程序编译完成后，写一个用户端程序加载程序并hook到相应的位置。

**loading**

```C
int bpf_prog_load(const char *file, enum bpf_prog_type type, struct bpf_object **pobj, int *prog_fd)
```

简单地提取file中的第一个bpf program, type设置其类型, 得到的bpf_object和program fd存放在后两个参数中, 返回值0为成功, 其他为errno

> 注: 从内核程序二进制文件(.o)到加载到内核完毕后, 程序经历了几个形态. bpf_object, bpf_program, fd
struct bpf_object 包含(多个)bpf program, (多个)map, section信息, elf信息, btf信息等等, 是整个文件的信息
>
> struct bpf_program 包含bpf insn, attach type, 重定位信息等等, 是一个bpf program的信息
>
> fd 加载完毕后的程序的文件描述符, bpf采用在内存中占用一定空间, 并使用一个匿名inode标记这块空间的方法来定位程序, map的定位方法相同. 在加载到这一步后, program和map都能挂载到bpffs文件系统下, 从而实现跨程序定位, 这种方法叫做"pinning", 实际上解决了fd生命周期和可见范围仅限于一个程序的问题.

```C
struct bpf_object *bpf_object__open_xattr(struct bpf_object_open_attr *attr)
```

根据参数读取二进制文件, 返回其bpf_object对象, 参数结构体包括文件名和程序类型, 如下.

```C
struct bpf_object_open_attr {
	const char *file;
	enum bpf_prog_type prog_type;
};
```

```C
bpf_object__for_each_program(prog, obj)
```

一个宏, 扩展为一个for循环, 使用bpf_program__next()遍历一个obj中的所有bpf_program, prog为一个bpf_program指针, 上述函数利用这个宏处理obj中的每个program, 并取出第一个program返回.

```C
int bpf_object__find_program_by_name(const struct bpf_object *obj, const char *name)
```

从obj中提取指定名称的program, 此处的name为函数名, 利用该函数可以提取一个文件中的特定program.

```C
int bpf_object__load(struct bpf_object *obj)
```

将一个obj加载到内核空间中

```C
int bpf_program__fd(const struct bpf_program *prog)
```

得到一个program的fd

**attaching**

```C
int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
```

将fd指定的program挂载到ifindex指定的iface上, flags为XDP_FLAGS_*(位于linux/if_link.h), 下面为一个处理其返回值的范例

```C
int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	/* Next assignment this will move into ../common/ */
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}
```

## map

### 创建map

map的声明应当放在内核程序中, 常用的有两种方式.

```C
struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct qname_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} dns_block_suffixes SEC(".maps");
```

```C
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};
```

两种方法都仅使用了bpf.h和bpf_helpers.h而未使用libbpf. 注意SEC的写法需要严格按照上面所展示的, "."不能混用. 错误为

```sh
libbpf: map 'xxxx': attr 'type': expected PTR, got 1.
```

### 使用map

map是内核端和用户端都能使用的数据结构, 内核端程序可以直接使用本文件内声明的map, 用户端程序或其他内核端程序想要访问则需要一些手段, 这是C变量的可见性决定的.

直接学习map的读写, 见[map的读写(使用helpers)](#map的读写使用helpers)

**在加载器中获取map fd**

加载器即为加载内核端程序的用户端程序, 其特殊性在于在加载时就要获取内核端程序的obj(fd), libbpf提供了从一个程序obj中获取它包含的map的函数. 

```C
struct bpf_map * bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name)

int bpf_object__find_map_fd_by_name(const struct bpf_object *obj, const char *name)
```

假设我们已经获取了程序obj, 可以通过这两个函数分别获得指定名字的map的bpf_map结构或直接获取fd

bpf_map结构见下

```C
struct bpf_map {
	int fd;
	char *name;
	int sec_idx;
	size_t sec_offset;
	int map_ifindex;
	int inner_map_fd;
	struct bpf_map_def def;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	void *priv;
	bpf_map_clear_priv_t clear_priv;
	enum libbpf_map_type libbpf_type;
	char *pin_path;
	bool pinned;
	bool reused;
};
```

使用该结构可以调用libbpf中的map相关功能的包装函数, 如resize, reuse, pin, unpin, 遍历map等.

如果直接获取fd(其实上述获取结构的同时也得到了fd), 就可以调用helpers[读写map](#map的读写使用helpers).


**pinning map**

为了方便, libbpf为struct bpf_map包装了一个函数, 实际调用了bpf的[bpf_obj_pin()](#pinning), 见下

```C
int bpf_map__pin(struct bpf_map *map, const char *path)
```

以及为整个obj pin所有map的函数

```C
int bpf_object__pin_maps(struct bpf_object *obj, const char *path)
```

map的unpin操作可以简单调用unlink实现, libbpf中的包装函数为

```C
int bpf_map__unpin(struct bpf_map *map, const char *path)
```

# libxdp

libxdp是在libbpf基础上, 扩充了程序加载和AF_XDP socket的库. 本文章主要介绍其将多个non-offload xdp程序加载到一个iface上的功能原理和使用方法. 可以通过两篇文档了解其全貌

[libxdp - library for attaching XDP programs and using AF_XDP sockets](https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/README.org)

[Protocol for atomic loading of multi-prog dispatchers](https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/protocol.org)

> 注: libxdp也对libbpf包装的单个程序读取, 加载的函数进行了进一步包装, 可以更明确更简单地完成前文所述libbpf完成的工作

## 多重attaching
参考xdp-tools中的[xdp-loader](https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader), 介绍libxdp加载多个程序的流程, 以便写出自己的多重加载程序.

### 加载程序

加载程序为加载器程序的第一步, 在libxdp库中, 我们的目标为使用已知的程序信息(文件名, 程序名, section名等), 创建一个 `struct xdp_program` 结构

libxdp中最通用的加载bpf程序函数为

```C
struct xdp_program *xdp_program__create(struct xdp_program_opts *opts)
```

从其参数 `struct xdp_program_opts` 的定义和说明可看出该函数的工作方式

```C
struct xdp_program_opts {
	size_t sz;
	struct bpf_object *obj;
	struct bpf_object_open_opts *opts;
	const char *prog_name;
	const char *find_filename;
	const char *open_filename;
	const char *pin_path;
	__u32 id;
	int fd;
	size_t :0;
};
```

该结构体的成员值的设置只能限于一下几种情况:
- @obj, @prog_name 使用obj中名为prog_name的程序创建xdp_program, prog_name是可选的, 如为空则选择obj中的第一个程序
- @find_filename, @prog_name, @opts 在环境变量LIBXDP_OBJECT_PATH中查找名为find_filename中名为prog_name的程序(同样可选), 可选地使用 `struct bpf_object_open_opts` 参数opts
- @open_filename, @prog_name, @opts 类似上个选项, 不过open_filename为程序文件的完整路径
- @pin_path 从pin_path所pin的程序读取结构
- @id 从ID指定的程序中读取结构
- @fd 从文件描述符指定的程序中读取结构

当设置为一种组合时, 未参与的成员变量应当置零

了解了该结构的设计, 就容易读懂 `xdp_program__create()` 的代码, 对应于上述6种情况的实际调用函数分别为

```C
struct xdp_program *xdp_program__create_from_obj(struct bpf_object *obj,
							const char *section_name,
							const char *prog_name,
							bool external)

static struct xdp_program *__xdp_program__find_file(const char *filename,
						    const char *section_name,
						    const char *prog_name,
						    struct bpf_object_open_opts *opts)

static struct xdp_program *__xdp_program__open_file(const char *filename,
						    const char *section_name,
						    const char *prog_name,
						    struct bpf_object_open_opts *opts)

struct xdp_program *xdp_program__from_pin(const char *pin_path)

struct xdp_program *xdp_program__from_id(__u32 id)

struct xdp_program *xdp_program__from_fd(int fd)
```

注意 `__xdp_program__find_file()` 和 `__xdp_program__open_file()` 的第2,3个参数section_name和prog_name只能设置其一, 在函数 `xdp_program__create_from_obj()` 种可看出其原因, 实际使用时可以用非内部的 `xdp_program__find_file()` 和 `xdp_program__open_file()`替代, 不过这两个函数都使用section_name, 已经变成deprecated, 新程序中可以考虑不使用.

### 设置程序Metadata

libxdp程序的metadata包括run priority和chain call actions, run_prio是加载多个程序时排序的依据, 值越低代表优先度越高. run_prio的默认值为50, 用一个uint来表示. 

chain_call_action是决定program的返回值如何影响调用链是否继续的参数. XDP程序的返回值如下

```C
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```
共有5种返回值, chain_call_action则利用uint的最低5位, 以位图方式保存. 例如, 如果我们将某个程序的XDP_PASS和XDP_TX设置为chain call enabled, 那么libxdp就会在该程序返回XDP_PASS或XDP_TX时继续调用下一个程序, 否则终止调用链, 并直接返回最终的返回值到内核. 此时该xdp_program结构中的chain_call_actions会被置为01100(二进制). 默认情况下, 只有XDP_PASS被置为enabled. 

有两种方式设置一个程序的metadata, 第一种是在内核端程序中使用宏来设置.

```C
struct {
	__uint(priority, 10);
	__uint(XDP_PASS, 1);
	__uint(XDP_DROP, 1);
} XDP_RUN_CONFIG(my_xdp_func);
```

这代表将(函数)名为"my_xdp_func"的程序的run_prio设置为10, XDP_PASS和XDP_DROP设置为chain call enabled. 在内核端使用时需要引用

```C
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>
```

另一种方式是在用户端程序中查看和设置metadata, 下列函数均来自libxdp

```C
unsigned int xdp_program__run_prio(const struct xdp_program *xdp_prog);
int xdp_program__set_run_prio(struct xdp_program *xdp_prog,
                              unsigned int run_prio);
bool xdp_program__chain_call_enabled(const struct xdp_program *xdp_prog,
				     enum xdp_action action);
int xdp_program__set_chain_call_enabled(struct xdp_program *prog,
                                        unsigned int action,
                                        bool enabled);
int xdp_program__print_chain_call_actions(const struct xdp_program *prog,
					  char *buf,
					  size_t buf_len);
```

### attaching

在准备好一系列xdp_program以及其metadata后, 就可以将它们挂载到hook上, libxdp使用一个bpf程序, 称为dispatcher, 它实际上利用内核的freplace类型程序, 将所有用户提供的程序加载到内核空间, 并逐个调用, 得到结果后按设置的chain_call_actions判断是否继续. dispatcher的详细介绍见[xdp dispatcher](#xdp-dispatcher). 

在真正attach之前, 需要考虑已经部署的xdp程序, 不同于raw bpf的情况, libxdp面对已经部署的程序不能直接进行替换, 而是将新旧程序同时部署. 然而这需要内核支持, 在内核版本5.10以上可以增量式地部署, 否则只能调用下述函数一次部署多个程序. 同时注意, 现版本不能将多个xdp程序offload. 

```C
int xdp_program__attach_multi(struct xdp_program **progs, 
				  size_t num_progs,
			      int ifindex, enum xdp_attach_mode mode,
			      unsigned int flags)
```

progs指向一个 `struct xdp_program` 数组, num_progs为program的个数, 在当前版本范围为1-10, ifindex代表网卡, mode见下, flags还未支持.

```C
enum xdp_attach_mode {
	XDP_MODE_UNSPEC = 0,
	XDP_MODE_NATIVE,
	XDP_MODE_SKB,
	XDP_MODE_HW
};
```

### map使用相关

需要特别注意，在第一步打开程序（open，create等等）过程后，bpf程序还未被加载入内核，此时去查找map fd的话会失败（返回-1），应在加载后再操作map。上面提到的 `xdp_program__attach_multi()` 函数中调用了 `xdp_multiprog__generate()` ，该函数又调用了 `xdp_multiprog__load()` ，该函数笼统地说是对 `bpf_object__load()` 在 `struct xdp_multiprog` 上的封装。因此，安装上面介绍的流程，必须在attach之后再进行map操作，也可以仿照 `xdp_program__attach_multi()` 的流程自行实现，并将map操作插入到load和attach之间，过于复杂此处不作考虑。

## 多重attaching实现原理

内核EBPF和开发EBPF程序主要依赖的libbpf库都不支持同时在同一网卡上加载多个xdp程序，libxdp使用了一种调度器（Dispatcher）方法解决了这一问题。假设用户要将三个xdp程序加载到网卡（分别为prog1，prog2，prog3），网卡接收到的数据包应依次经过三个xdp程序的处理，每个程序的处理结果都有可能是PASS，DROP或REDIRECT等等。libxdp的解决方法是，使用一个专门的xdp程序，称为dispatcher，在得到freplace类型程序的支持后该程序能够调用其他xdp程序，并获取其处理结果，以进行进一步判断。libxdp只将该dispatcher挂载到网卡的驱动上，并将要调用的xdp程序加载到内核(即prog1，prog2，prog3)。用户可以指定每个xdp程序的优先级和chain call action，chain call action是从xdp处理结果（PASS，DROP等）到是/否继续调用下一个程序的映射，决定了dispatcher在接收到xdp程序处理结果后的行为，如果不继续调用则将处理结果和报文返回到内核。

dispatcher接收到报文后，按照用户指定的优先级调用prog1，同时将报文传入；得到prog1的处理结果后，根据用户给出的chain call action判断是否调用下一个程序，以此类推。libxdp允许了动态地选择加载哪些xdp程序，也可以说是允许了xdp程序功能的动态变化。