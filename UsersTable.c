/*
htop - UsersTable.c
(C) 2004-2011 Hisham H. Muhammad
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "config.h" // IWYU pragma: keep

#include "UsersTable.h"

#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "XUtils.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

UsersTable* UsersTable_new(void) {
   UsersTable* this;
   this = xMalloc(sizeof(UsersTable));
   this->users = Hashtable_new(10, true);
   return this;
}

void UsersTable_delete(UsersTable* this) {
   Hashtable_delete(this->users);
   free(this);
}


char* UsersTable_getRef(UsersTable* this, unsigned int uid) {
   char* name = Hashtable_get(this->users, uid);

   if (name == NULL) {

#ifdef HTOP_STATIC
      // Fast Path: Standard local users (< 65536)
      if (uid < 65536) {
         const struct passwd* userData = getpwuid(uid);
         if (userData != NULL) {
            name = xStrdup(userData->pw_name);
         }
      }

      // Safe Path: High UIDs via isolated process with strict privilege dropping
      if (name == NULL) {
         int pipefd[2];
         if (pipe(pipefd) == 0) {
            pid_t pid = fork();

            if (pid == 0) {
               close(pipefd[0]);
               dup2(pipefd[1], STDOUT_FILENO);
               close(pipefd[1]);

               // SECURITY: Drop privileges before execution.
               uid_t target_uid = getuid();
               gid_t target_gid = getgid();

               if (target_uid == 0) {
                  struct passwd* pw = getpwnam("nobody");
                  if (pw) {
                     target_uid = pw->pw_uid;
                     target_gid = pw->pw_gid;
                  } else {
                     target_uid = 65534; // Fallback (standard nobody UID)
                     target_gid = 65534;
                  }
               }

               // Drop group privileges, then user privileges
               if (setgid(target_gid) != 0) _exit(1);
               if (setuid(target_uid) != 0) _exit(1);

               char uid_str[32];
               xSnprintf(uid_str, sizeof(uid_str), "%u", uid);

               char arg0[] = "getent";
               char arg1[] = "passwd";
               char *const args[] = { arg0, arg1, uid_str, NULL };

               execvp("getent", args);
               _exit(127);
            }
            else if (pid > 0) {
               close(pipefd[1]);

               FILE* fp = fdopen(pipefd[0], "r");
               if (fp) {
                  char buffer[1024];
                  if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                     char* colon = strchr(buffer, ':');
                     if (colon) {
                        *colon = '\0';
                        name = xStrdup(buffer);
                     }
                  }
                  fclose(fp);
               } else {
                   close(pipefd[0]);
               }
               waitpid(pid, NULL, 0);
            }
         }
      }

      // Fallback: Raw UID
      if (name == NULL) {
         char buf[32];
         xSnprintf(buf, sizeof(buf), "%u", uid);
         name = xStrdup(buf);
      }

#else
      const struct passwd* userData = getpwuid(uid);
      if (userData != NULL) {
         name = xStrdup(userData->pw_name);
      }
#endif

      if (name != NULL) {
         Hashtable_put(this->users, uid, name);
      }
   }
   return name;
}

inline void UsersTable_foreach(UsersTable* this, Hashtable_PairFunction f, void* userData) {
   Hashtable_foreach(this->users, f, userData);
}
