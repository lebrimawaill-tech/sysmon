/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Execute socket-requested open/read/write syscalls and report results and
 * side effects to the CLI test driver.
 *
 * This worker performs no ioctls or sysmon.log writes. Socket send/recv
 * control messages still work when its read/write syscalls are denied.
 */
int main(int argc, char **argv)
{
	char command[16], message[256], buffer[4], actual[3];
	int socket_fd, fixture;
	ssize_t count;

	if (argc != 3)
		return 2;
	socket_fd = atoi(argv[1]);
	fixture = open(argv[2], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (fixture < 0)
		return 2;
	if (send(socket_fd, "ready", 5, MSG_NOSIGNAL) != 5)
		return 2;
	while ((count = recv(socket_fd, command, sizeof(command) - 1, 0)) > 0) {
		struct stat info;
		long result;
		int error, side_effects, length;

		command[count] = '\0';
		if (!strcmp(command, "quit"))
			break;
		if (strcmp(command, "open") && strcmp(command, "read") && strcmp(command, "write"))
			return 2;
		/* Reset with unmonitored operations, without producing fake observations. */
		if (pwrite(fixture, "abc", 3, 0) != 3 || ftruncate(fixture, 3) ||
		    lseek(fixture, 0, SEEK_SET) != 0)
			return 2;
		memcpy(buffer, "???", 4);
		errno = 0;
		if (!strcmp(command, "open"))
			result = syscall(SYS_open, argv[2], O_RDWR | O_TRUNC, 0);
		else if (!strcmp(command, "read"))
			result = syscall(SYS_read, fixture, buffer, 3);
		else
			result = syscall(SYS_write, fixture, "XYZ", 3);
		error = errno;
		if (!strcmp(command, "open") && result >= 0)
			close((int)result);
		memset(actual, 0, sizeof(actual));
		if (fstat(fixture, &info) || pread(fixture, actual, 3, 0) < 0)
			return 2;
		side_effects = result < 0 && (info.st_size != 3 ||
			memcmp(actual, "abc", 3) || lseek(fixture, 0, SEEK_CUR) != 0 ||
			memcmp(buffer, "???", 4));
		length = snprintf(message, sizeof(message),
			"{\"pid\":%d,\"op\":\"%s\",\"result\":%ld,\"errno\":%d,\"side_effects\":%d}",
			getpid(), command, result, error, !!side_effects);
		if (length < 0 || (size_t)length >= sizeof(message) ||
		    send(socket_fd, message, (size_t)length, MSG_NOSIGNAL) != length)
			return 2;
	}
	close(fixture);
	close(socket_fd);
	return count < 0 ? 2 : 0;
}
