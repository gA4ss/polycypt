#ifndef POLYCYPT_H
#define POLYCYPT_H

#include <polycypt_error.h>
#include <polycypt_factory.h>

#include <vector>
#include <string>

#ifdef _MSC_VER
#include <memory>
#endif

typedef struct {
	int factory;			/* -1 : random */
} polycypt_config;

class polycypt {
public:
	polycypt();
	polycypt(const polycypt_config &config);
	virtual ~polycypt();
  bool run(const std::string &output_dir, const std::string &template_dir);
  int error();

private:
	void reset();
  void load_algs();
	int random(size_t n = 100);
  
private:
	polycypt_config _config;
  std::vector<std::shared_ptr<polycypt_factory> > _factories;
	int _error;
};


#endif
