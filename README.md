## 这是一个用 C++实现 mini debugger 的小项目
参考：https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/

上述博客介绍了一些列步骤以及各个步骤的源码，然而道路是曲折的，bug 还是多的（我有充分证据，博客作者并没有验证他的代码，很多处都是错的，需要读者自己找）。

## 本项目 main 分支没有任何代码，代发放在了 linux_version 分支
事实上，我很少参考作者放的 git 仓库代码，我仅仅参考了作者的博客中的代码，那已经足够了。

我编写了很系统的 CMakeLists.txt 文件，我认为这样非常有利于清晰地组织和修改。你可以直接克隆这些代码，然后在和最外层 CMakeLists.txt的目录中：

```bash
cmake -B cmake
cmake --build build

cd ./bin
./minidbg stack

```
直接调试，我已经解决了所有的疑难杂症。

## 想法
mini debugger 是用 C++写的，事实上，你可以用任何能调用 libelfin、lineniose 的库的语言（C）都可以实现，这里面牵扯到的知识尤其是关于ELF、DWARF等，和 C++没有任何关系，C++只是一个载体。这个项目有点像系统编程，我不知道为什么有人将它归类于 C++实践类。如果练习 C++ 编程，这绝对不是最合适的。

如果你对一下不熟悉，我建议你认真学习这个项目，通过这个项目可以学到：
- CMakeList.txt 的编写
- 动态库、静态库的链接（基于 cmake？）
- OS 对程序的加载与运行
- stack frame 的组织方式等等
- 当然了，debugger 的原理！！！





