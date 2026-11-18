// Independent-include check for <megohttp/task.hpp>.
//
// The header must compile on its own in BOTH modes: with coroutines enabled
// (C++20) and disabled (C++17), where it must contribute nothing but the
// include guard.
#include <megohttp/task.hpp>

#if MEGOHTTP_HAS_COROUTINES
// The type must be complete enough to name.
static_assert(sizeof(megohttp::Task<int>) > 0, "Task<int> must be a complete type");
#endif

int main() { return 0; }
