void a() {
  int foo = 1;
  int foo1 = 1;
  int foo2 = 1;
  int foo3 = 1;
}

void b() {
  int foo = 1;
  int foo1 = 1;
  a();
  int foo2 = 1;
  int foo3 = 1;
}

void c() {
  int foo = 1;
  int foo1 = 1;
  b();
  int foo2 = 1;
  int foo3 = 1;
}

void d() {
  int foo = 1;
  int foo1 = 1;
  c();
  int foo2 = 1;
  int foo3 = 1;
}

void e() {
  int foo = 1;
  int foo1 = 1;
  d();
  int foo2 = 1;
  int foo3 = 1;
}

void f() {
  int foo = 1;
  int foo1 = 1;
  e();
  int foo2 = 1;
  int foo3 = 1;
}

int main() {
  int foo = 1;
  int foo1 = 1;
  int foo2 = 1;
  int foo3 = 1;
  f();
}