#include <iostream>
inline void print1() { std::cerr << "helloworld1.\n"; }
inline void print2() { std::cerr << "helloworld2.\n"; }
inline void print3() { std::cerr << "helloworld3.\n"; }
inline void print4() { std::cerr << "helloworld4.\n"; }
int main() {
  std::cerr << "hello,world0.\n";
  std::cerr << "hello,world1.\n";
  std::cerr << "hello,world2.\n";
  std::cerr << "hello,world3.\n";
  std::cerr << "hello,world4.\n";
  for (int i = 0; i < 5; i++) {
    std::cerr << "hello,world." << i << std::endl;
  }
  print1();
  print2();
  print3();
  print4();
  return 0;
}