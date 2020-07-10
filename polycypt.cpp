#include <polycypt.h>
#include <polycypt_alg0.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>

polycypt::polycypt()
{
  load_algs();
}

polycypt::polycypt(const polycypt_config & config)
{
  load_algs();
	_config = config;
}

polycypt::~polycypt()
{
}

bool polycypt::run(const std::string &output_dir, const std::string &template_dir)
{
	reset();
	int factory = _config.factory;
	if (factory == -1) {
		factory = random(_factories.size());
	}

	std::shared_ptr<polycypt_factory> maker = _factories[factory];
	if (maker->make(output_dir, template_dir, true) == false) {
		return false;
	}
	return true;
}

int polycypt::error() {
  return _error;
}

void polycypt::reset()
{
	_error = POLYCYPT_ERROR_SUCCESS;
}

void polycypt::load_algs() {
  _factories.push_back(std::shared_ptr<polycypt_alg0>(new polycypt_alg0()));
}

int polycypt::random(size_t n)
{
	return rand() % n;
}

