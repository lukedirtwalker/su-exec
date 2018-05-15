/* set user and group id and exec */

#define _GNU_SOURCE

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENV_VAR "SU_EXEC_USERSPEC"

static char *argv0;

static void usage(int exitcode)
{
	printf("Usage: %s=user:group %s command [args]\n", ENV_VAR, argv0);
	exit(exitcode);
}

int main(int argc, char *argv[])
{
	char *user, *group, **cmdargv;
	char *userspec;

	argv0 = argv[0];
	if (argc < 2) {
		usage(0);
	}
	cmdargv = &argv[1];

	/*
	 * It's not safe to access the environment if running suid, so use
	 * secure_getenv to prevent that.
	 */
	userspec = secure_getenv(ENV_VAR);
	if (userspec == NULL) {
		errx(1, "%s env var not set", ENV_VAR);
	}
	if (strnlen(userspec, 50) == 0) {
		errx(1, "%s env var is empty", ENV_VAR);
	}

	user = userspec;
	group = strchr(user, ':');
	if (group) {
		*group++ = '\0';
	}

	struct passwd *pw = getpwnam(user);
	if (pw == NULL) {
		errx(2, "Unknown user '%s'", user);
	}
	uid_t uid = pw->pw_uid;
	gid_t gid = pw->pw_gid;

	setenv("HOME", pw != NULL ? pw->pw_dir : "/", 1);

	if (group && group[0] != '\0') {
		/* group was specified, ignore grouplist for setgroups later */
		pw = NULL;

		struct group *gr = getgrnam(group);
		if (gr == NULL) {
			errx(2, "Unknown group '%s'", group);
		}
		gid = gr->gr_gid;
	}

	if (pw == NULL) {
		if (setgroups(1, &gid) < 0) {
			err(1, "setgroups(%i)", gid);
		}
	} else {
		int ngroups = 0;
		gid_t *glist = NULL;

		while (1) {
			int r = getgrouplist(pw->pw_name, gid, glist, &ngroups);

			if (r >= 0) {
				if (setgroups(ngroups, glist) < 0) {
					err(1, "setgroups");
				}
				break;
			}

			glist = realloc(glist, ngroups * sizeof(gid_t));
			if (glist == NULL) {
				err(1, "malloc");
			}
		}
	}

	if (setgid(gid) < 0) {
		err(1, "setgid(%i)", gid);
	}

	if (setuid(uid) < 0) {
		err(1, "setuid(%i)", uid);
	}

	execvp(cmdargv[0], cmdargv);
	err(1, "%s", cmdargv[0]);

	return 1;
}

// vim: noet ts=4 sw=4
