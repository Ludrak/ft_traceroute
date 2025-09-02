.PHONY: clean fclean re all check_sources check_headers

# Name of target executable
NAME		= ft_traceroute

# Locations 
SRC_DIR		= src
INC_DIR		= inc
BIN_DIR		= bin
LIB_DIR		= lib

# Sources & Headers 
# - fill only with name of the file
# - make will check for the file in SRC_DIR
# - use "-" if empty
SRCS=				main.c context.c packet.c packet_error.c checksum.c options.c\
					net_utils.c time_utils.c print_util.c print_util_network.c\

# Librarys (only for local archives in project folder)
LIBRARYS	= 

CLANG		=	gcc
CPP_FLAGS	=	-Wextra -Wall -Werror #-g3 -fsanitize=address
CPP_IFLAGS	=	

CPP_LFLAGS	= -lm

# Fancy prefixes 
PREFIX_PROJECT=[\033[1;32m$(NAME)\033[0m]
PREFIX_COMP=\033[1;30m-\033[0m-\033[1;37m>\033[0m[\033[1;32m✔\033[0m]
PREFIX_LINK=[\033[1;32mLINK\033[0m]
PREFIX_INFO=[\033[1;32mINFO\033[0m]
PREFIX_WARN=[\033[0;33mWARN\033[0m]
PREFIX_ERROR=[\033[0;91mERROR\033[0m]
PREFIX_DUPL=[\033[1;33mDUPLICATES\033[0m]
PREFIX_CLEAN=[\033[1;31mCLEAN\033[0m]


############################################################################################
# AUTOMATIC VARIABLES
############################################################################################

# Automatic variables
OBJS		= $(addprefix $(BIN_DIR)/$(SRC_DIR)/, $(SRCS:.c=.o))
DEPS		= $(OBJS:.o=.d)
LIBS		= $(addprefix $(LIB_DIR)/, $(LIBRARYS))

# Automatic flags
CPP_IFLAGS	+= $(addprefix -I, $(INC_DIR))
CPP_LFLAGS	+= $(addprefix -L, $(LIB_DIR))

############################################################################################
# RULES
############################################################################################

all: $(NAME)

$(NAME): $(OBJS) $(LIBS)
	@echo "$(PREFIX_LINK) Linking $(NAME)"
	@$(CLANG) $(CPP_FLAGS) $(OBJS) $(CPP_LFLAGS) -o $(NAME)
	@echo "$(PREFIX_PROJECT) $(NAME) compiled successfully"

$(BIN_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "$(PREFIX_COMP) Compiling $<"
	@$(CLANG) $(CPP_FLAGS) $(CPP_IFLAGS) -MMD -c $< -o $@

$(BIN_DIR)/$(SRC_DIR)/util/%.o: $(SRC_DIR)/util/%.c
	@mkdir -p $(dir $@)
	@echo "$(PREFIX_COMP) Compiling $<"
	@$(CLANG) $(CPP_FLAGS) $(CPP_IFLAGS) -MMD -c $< -o $@

$(BIN_DIR)/$(SRC_DIR)/util/print/%.o: $(SRC_DIR)/util/print/%.c
	@mkdir -p $(dir $@)
	@echo "$(PREFIX_COMP) Compiling $<"
	@$(CLANG) $(CPP_FLAGS) $(CPP_IFLAGS) -MMD -c $< -o $@

clean:
	@echo "$(PREFIX_CLEAN) Cleaning object files"
	@rm -rf $(BIN_DIR)

fclean: clean
	@echo "$(PREFIX_CLEAN) Cleaning $(NAME)"
	@rm -f $(NAME)

re: fclean all

# Include dependency files
-include $(DEPS)

############################################################################################
# CHECKS
############################################################################################

check_sources:
	@echo "$(PREFIX_INFO) Checking for source files..."
	@for src in $(SRCS); do \
		if [ ! -f "$(SRC_DIR)/$$src" ]; then \
			echo "$(PREFIX_ERROR) Source file $(SRC_DIR)/$$src not found"; \
			exit 1; \
		fi; \
	done
	@echo "$(PREFIX_INFO) All source files found"

check_headers:
	@echo "$(PREFIX_INFO) Checking for header files..."
	@find $(INC_DIR) -name "*.h" -exec echo "$(PREFIX_INFO) Found header: {}" \;
