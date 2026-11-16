#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * TEST ONLY: deterministic libgcrypt entropy for differential testing.
 *
 * Loading this shared object destroys all cryptographic security in the
 * process.  Refuse to initialize without an unmistakable opt-in, and abort if
 * GnuPG requests an entropy path the harness has not modeled.
 */

static uint64_t offset;
static int nonzero_pattern;

static void require_opt_in(void)
{
  const char *value = getenv("LIZARD_GPG_TEST_RNG");
  if (!value || strcmp(value, "INSECURE_DIFFERENTIAL_TEST_ONLY"))
    {
      static const char message[] =
        "test RNG hook refused: missing explicit test-only opt-in\n";
      write(STDERR_FILENO, message, sizeof(message) - 1);
      _exit(99);
    }
}

static uint64_t parse_start(void)
{
  const char *value = getenv("LIZARD_GPG_TEST_RNG_START");
  char *end = NULL;
  unsigned long long parsed;

  if (!value || !*value)
    return 0;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno || !end || *end)
    {
      static const char message[] = "test RNG hook refused invalid start\n";
      write(STDERR_FILENO, message, sizeof(message) - 1);
      _exit(98);
    }
  return (uint64_t)parsed;
}

__attribute__((constructor)) static void initialize(void)
{
  require_opt_in();
  offset = parse_start();
  nonzero_pattern = !!getenv("LIZARD_GPG_TEST_RNG_NONZERO");
}

static void fill(void *buffer, size_t length, const char *operation)
{
  unsigned char *bytes = buffer;
  uint64_t start = offset;
  size_t i;

  require_opt_in();
  for (i = 0; i < length; i++)
    {
      bytes[i] = nonzero_pattern
        ? (unsigned char)((offset % 255) + 1)
        : (unsigned char)(offset & 0xff);
      offset++;
    }

  if (getenv("LIZARD_GPG_TEST_RNG_LOG"))
    dprintf(STDERR_FILENO, "LIZARD_TEST_RNG %s offset=%llu length=%zu\n",
            operation, (unsigned long long)start, length);
}

void gcry_randomize(void *buffer, size_t length, int level)
{
  (void)level;
  fill(buffer, length, "gcry_randomize");
}

void gcry_create_nonce(void *buffer, size_t length)
{
  fill(buffer, length, "gcry_create_nonce");
}

void *gcry_random_bytes(size_t length, int level)
{
  void *(*allocate)(size_t);
  void *buffer;

  (void)level;
  allocate = dlsym(RTLD_NEXT, "gcry_malloc");
  if (!allocate)
    _exit(97);
  buffer = allocate(length);
  if (buffer)
    fill(buffer, length, "gcry_random_bytes");
  return buffer;
}

void *gcry_random_bytes_secure(size_t length, int level)
{
  void *(*allocate)(size_t);
  void *buffer;

  (void)level;
  allocate = dlsym(RTLD_NEXT, "gcry_malloc_secure");
  if (!allocate)
    _exit(96);
  buffer = allocate(length);
  if (buffer)
    fill(buffer, length, "gcry_random_bytes_secure");
  return buffer;
}

void gcry_mpi_randomize(void *mpi, unsigned int nbits, int level)
{
  static const char message[] =
    "test RNG hook refused unmodeled MPI randomization\n";
  (void)mpi;
  (void)nbits;
  (void)level;
  write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(95);
}
