#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include <errno.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>

/**
 * Homebrew assert for this program. Just output an error and end the program
 * if the condition isn't met.
 */
#define FIFOWRITER_ASSERT(condition, ...) \
  if (!(condition)){ \
    fprintf(stderr, __VA_ARGS__); \
    exit(-1); \
  }

#define FIFOWRITER_MEMORY_FAILED "Malloc failed"
#define FIFOWRITER_OPTIONS_NULL "Options must not be NULL. Use parse_options(argc, argv) first."


/**
 * Verbose-mode output.
 */
int g_verbose = 0;
#define vbprintf(...) \
  if (g_verbose > 0) { \
    fprintf(stderr, __VA_ARGS__); \
  }


/**
 * Data structure for configurable options from the commandline or other.
 */
typedef struct {
  char* output; /* -o output */
  int output_truncate; /* -t */
  int output_create; /* -c */
  char* input; /* -i input */
  size_t buffer_size; /* -b buffersize */
  int buffer_lines; /* -l */
  int buffer_discard; /* -d */
  int verbose; /* -v */
} options_t;

void free_options(options_t*);
void show_usage(const char *);

/**
 * Parse commandline options from argc/argv. Return a pointer to valid options,
 * otherwise it returns NULL.
 */
#define GETOPT_OPTIONS "o:b:ldtci:vh"
options_t* parse_options(int ac, char *av[]){
  int opt;

  options_t *options = malloc(sizeof(options_t));
  FIFOWRITER_ASSERT(options != NULL, FIFOWRITER_MEMORY_FAILED);

  memset(options, 0, sizeof(options_t));

  /* Defaults */
  options->output_truncate = 0;
  options->output_create = 0;
  options->buffer_size = 1024;
  options->buffer_lines = 0;
  options->buffer_discard = 0;
  options->verbose = 0;

  while ((opt = getopt(ac, av, GETOPT_OPTIONS)) != -1){
    switch (opt){
      case 'o':
        options->output = strdup(optarg);
        FIFOWRITER_ASSERT(options->output != NULL, FIFOWRITER_MEMORY_FAILED);
        break;

      case 'i':
        options->input = strdup(optarg);
        FIFOWRITER_ASSERT(options->input != NULL, FIFOWRITER_MEMORY_FAILED);
        break;

      case 'b':
        options->buffer_size = atoi(optarg);
        break;

      case 'l':
        options->buffer_lines = 1;
        break;

      case 'd':
        options->buffer_discard = 1;
        break;

      case 't':
        options->output_truncate = 1;
        break;

      case 'c':
        options->output_create = 1;
        break;

      case 'v':
        options->verbose = 1;
        break;

      case 'h':
        show_usage(av[0]);
        exit(0);
        break;
    }
  }

  /* Ensure buffer size is big enough. */
  if (options->buffer_size < 1024){
    free_options(options);
    fprintf(stderr, "Minimum buffer size supported is 1024 bytes but a buffer size of %luB was requested.",
      options->buffer_size);
    return NULL;
  }

  return options;
}

/**
 * Free the memory and close up any resources associated with the options given.
 */
void free_options(options_t *options){
  FIFOWRITER_ASSERT(options != NULL, FIFOWRITER_OPTIONS_NULL);

  if (options->output != NULL)
    free(options->output);
  if (options->input != NULL)
    free(options->input);

  free(options);
}

/**
 * Simply show program usage and exit.
 */
void show_usage(const char *name){
  fprintf(stderr, "Usage: %s [-tcldvh] [-b buffersize] [-i inputfile] [-o outputfile]\n\n", name);
  fprintf(stderr,
    "fifowriter writes the contents of its input to an output as it comes in, but\n"\
    "allows the output and inputs to be fifos but is resilient to fifo read disconnection.\n\n"\
    "\t-t\tTruncate the output file.\n" \
    "\t-c\tCreate the output file if it doesn't exist.\n" \
    "\t-l\tLine-buffer when writing to the output. (TODO)\n" \
    "\t-d\tDiscard buffer contents when unable to write it.\n" \
    "\t-v\tVerbose messages on stderr.\n" \
    "\t-h\tShow usage.\n" \
    "\t-b\tSpecify the internal buffer size. (1024 bytes by default)\n" \
    "\t-i\tSpecify the input file to write to the output. (STDIN by default)\n" \
    "\t-o\tSpecify the output file to write to. (STDOUT by default)\n"
    );
}

/* Opens an input. Use stdin unless options specify an input file. */
int fifowriter_input_open(options_t *options){
  FIFOWRITER_ASSERT(options != NULL, FIFOWRITER_OPTIONS_NULL);

  const char *file = options->input;
  if (file != NULL){
    return open(file, O_RDONLY);
  } else {
    return STDIN_FILENO;
  }
}

/* Opens an output. Use stdout unless options specify an output file. */
int fifowriter_output_open(options_t *options){
  FIFOWRITER_ASSERT(options != NULL, FIFOWRITER_OPTIONS_NULL);

  const char *file = options->output;
  if (file != NULL){
    int open_options = O_WRONLY|O_NONBLOCK;

    if (options->output_truncate){
      open_options |= O_TRUNC;
    }
    if (options->output_create){
      open_options |= O_CREAT;
    }

    return open(file, open_options);
  } else {
    return STDOUT_FILENO;
  }
}

/* Close an input or output. It will no close STDIN or STDOUT. */
void fifowriter_close(int fd){
  if (fd != STDOUT_FILENO && fd != STDIN_FILENO && fd >= 0){
    close(fd);
  }
}

/**
 * Reads from the input and writes to the output when output is available.
 * Based on process options, the write operation will line-buffer, or it
 * may discard the contents of the buffer if nothing is available to write
 * to.
 */
void fifowriter_process(options_t *options){
  FIFOWRITER_ASSERT(options != NULL, FIFOWRITER_OPTIONS_NULL);

  char *buffer = malloc(options->buffer_size);
  size_t buffer_used = 0;
  FIFOWRITER_ASSERT(buffer != NULL, FIFOWRITER_MEMORY_FAILED);

  int input_fd = fifowriter_input_open(options);
  int input_eof = 0;
  int output_fd = -1;

  /* Run until the input and buffer are exhausted. (if() break) */
  for (;;){
    /* Attempt to open the output if it's not open already. */
    if (output_fd < 0){
      output_fd = fifowriter_output_open(options);
    }

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(input_fd, &read_set);

    fd_set write_set;
    FD_ZERO(&write_set);
    if (output_fd >= 0){
      FD_SET(output_fd, &write_set);
    }

    struct timeval timeout = {
      .tv_sec = 0,
      .tv_usec = 500*1000,
    };

    /* Block until there's stuff to read or ability to write to the output fd. */
    select(FD_SETSIZE, &read_set, &write_set, NULL, &timeout);

    /* Read from the stdin to the buffer if there's stuff to read and room to buffer it. */
    if (!input_eof && FD_ISSET(input_fd, &read_set) && buffer_used < options->buffer_size){
      ssize_t bytes_read = read(input_fd, buffer + buffer_used, options->buffer_size - buffer_used);
      buffer_used += bytes_read;

      /* Check for EOF. */
      if (bytes_read == 0){
        vbprintf("Input just reached end of file.\n");
        input_eof = 1;
      }
    }

    /* Write to the output anything in the buffer. */
    if (buffer_used > 0){
      int process_discard = 0;

      /* If output is available, let's write from the buffer. */
      if (output_fd > 0 && FD_ISSET(output_fd, &write_set)){
        vbprintf("Attempting to write %ld bytes. ", buffer_used);
        ssize_t bytes_written = write(output_fd, buffer, buffer_used);

        /* Happy path is some or all of the buffer was written... */
        if (bytes_written > 0) {
          vbprintf("%ld bytes written.\n", bytes_written);
          /* Adjust the buffer for the bytes that were written. */
          if (buffer_used - bytes_written > 0){
            memmove(buffer, buffer + bytes_written, buffer_used - bytes_written);
          }
          buffer_used -= bytes_written;
        }
        /* Error writing. */
        else if (bytes_written == -1){
          vbprintf("Error writing: %s\n", strerror(errno));

          /* When the error is not EAGAIN we'll close the output so it can be re-opened. */
          if (errno != EAGAIN) {
            fifowriter_close(output_fd);
            output_fd = -1;
          }

          process_discard = 1;
        }
      }
      /* No output is available. */
      else {
        process_discard = 1;
      }

      if (process_discard && options->buffer_discard){
        vbprintf("Discarding %ld buffered bytes.\n", buffer_used);
        buffer_used = 0;
      }
    }

    /* If the input has eof'd and there's no buffer left, we're done. */
    if (input_eof && buffer_used == 0){
      vbprintf("Ending because input is eof and there's no buffer left.");
      break;
    }
  }

  fifowriter_close(output_fd);
  fifowriter_close(input_fd);
  free(buffer);
}


/**
 * Signal trap for SIGPIPE. Prevents the program from halting when the process
 * reading the fifo disconnects. (e.g., broken pipe...)
 */
void signal_pipe(int signal){
  vbprintf("Signal received: %d\n", signal);
}




/**
 * Entrypoint.
 */
int main(int argc, char *argv[]){
  options_t *options;

  /* Get option information from the command line. */
  if ((options = parse_options(argc, argv)) == NULL){
    show_usage(argv[0]);
    exit(-1);
  }

  /* Turn on verbose if verbose was requested. */
  g_verbose = options->verbose;

  /* Begin trapping SIGPIPE and process the input. */
  signal(SIGPIPE, signal_pipe);
  fifowriter_process(options);

  /* Clean up. */
  free_options(options);
  options = NULL;

  return 0;
}

/* vim: set sw=2 ts=2 expandtab : */
