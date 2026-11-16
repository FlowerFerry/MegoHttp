// Independent-include check (spec 13.6): this TU includes exactly one public
// header and nothing else. If the header is not self-contained, this fails to
// compile even though every other TU in the project still builds.
#include <megohttp/content_range.hpp>
