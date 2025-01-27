NAME		=	ft_malcolm
CC			=	clang
CFLAGS		=	-Wall -Wextra -Werror -g

SRCS_FILES	=	\
				arg_validation.c \
				arp_spoof.c \
				datatype_conversion.c \
				main.c \
				packet_reader.c \
				print_utils.c \
				syscall_impl.c

OBJS_DIR	=	objs/
OBJS_FILES	=	$(SRCS_FILES:.c=.o)
OBJS		=	$(addprefix $(OBJS_DIR), $(OBJS_FILES))
INC			= ft_malcolm.h

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $@

$(OBJS_DIR)%.o: %.c $(INC)
	mkdir -p $(OBJS_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re