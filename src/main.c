#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>

#define ENC_EXTENSION           ".ebnp"
#define ENC_DIR                 "enc_"
#define DEC_DIR                 "dec_"
#define BUF_PATH                PATH_MAX
#define KEY_LENGTH              256
#define INPUT_FILES_MAX         100
#define INPUT_ARGUMENTS_MAX     6
#define NUMBER_OF_FILES         65346
#define PROG_NAME               "nongrata"
#define END_FILE_MSG            "NaNgrata"  // every encrypted file will contain it
#define MAGIC_NUMBER            0x11        /*
                                             *  special number separates previous extension
                                             *  of file (contained in every enc. file) and
                                             *  encrypted data of file
                                             */

#define MEM_FAILED(ptr) if (ptr == NULL) {      \
    fprintf(stderr, "Can't malloc memmory\n");  \
    exit(EXIT_FAILURE); }                           // macros to avoid malloc fail

struct tm get_cur_date(void);

int get_input_file(int, char **, char **);
int search_enc_ext(char *);
int file_count_in_dir(const char *, struct dirent **);

char *get_cur_path_al(void);
char *cat_path_al(char *, char *);
char *cat_src_path_al(char *, char *);
char *enc_ext_del_al(char *);
char *enc_ext_add_al(char *);
char *create_name_dec_al(char *, char *);
char *create_name_enc_al(char *);
char *create_dir_al(int,  char *, struct tm);
char *get_file_ext_al(char *);
char *get_ext_inside_file_al(FILE *, long long);

unsigned long get_key(char *);

long long get_file_length(char *);
long long check_msg(FILE *, long long);
long long add_msg_to_file(FILE *, long long);
long long add_ext_to_file(FILE *, char *, long long);

void make_enc_dec(FILE *, long long, unsigned long, char *, char *);
void paths_output(char *, char *, char *, int, int);
void output_about_program(void);
void get_file_data(FILE *, char *, long long);
void fun_fflush_stdin(void);


int main(int argc, char *argv[])
{
    FILE *fp, *new_fp;
    struct dirent *entry[NUMBER_OF_FILES];                  // contains file name in dir
    struct stat *sb;
    struct tm tm;

    char *new_file_name = NULL;
    char *file_data     = NULL;
    char *src_path      = NULL;
    char *dest_path     = NULL;
    char *cur_path      = NULL;
    char *extension     = NULL;
    char *tmp_ptr       = NULL;
    char key[KEY_LENGTH];

    char *input_file[INPUT_FILES_MAX];
    char *not_open_file[NUMBER_OF_FILES];
    char *not_enc_file[NUMBER_OF_FILES];
    char *alr_enc_file[NUMBER_OF_FILES];
    char *folder[NUMBER_OF_FILES];
    char *input_arg[INPUT_ARGUMENTS_MAX] = {"-a", "-p", "-t", "-e", "-d", "-h"};

    int folder_count            = 0;
    int alr_enc_file_count      = 0;
    int not_enc_file_count      = 0;
    int not_open_file_count     = 0;
    int entry_file_count        = 0;
    int input_file_count        = 0;
    int flag_dest_path          = 0;
    int flag_src_path           = 0;
    int flag_encrypt            = 0;
    int flag_decrypt            = 0;
    int tmp_count               = 0;
    int tmp_ch;

    unsigned long key_len       = 0;
    unsigned int arg_bit        = 0;

    long long file_len          = 0;


    output_about_program();

    if (argc == 1) {
        printf("Incorrect input\n");
        exit(EXIT_FAILURE);
    }

    // become all possible arguments
    for (int i = 1; i < argc; i++)
        for (int j = 0; j < INPUT_ARGUMENTS_MAX; j++)
            if (!strcmp(argv[i], input_arg[j])) {
                if (j == 0)
                    arg_bit |= 1;   // argument -a
                else if (j == 1)
                    arg_bit |= 2;   // argument -p
                else if (j == 2)
                    arg_bit |= 4;   // argument -t
                else if (j == 3)
                    arg_bit |= 8;   // argument -e
                else if (j == 4)
                    arg_bit |= 16;  // argument -d
                else if (j == 5) {
                    arg_bit = 425;  // argument -h
                    break;
                }
            }

    if (arg_bit == 425) { // argument -h
        printf(" nongrata project - v. nongrata_1.3 (2019 August 20)      \n\n"
               " Arguments:                                               \n"
               "    -a         All files                                  \n"
               "    -p         The path where the file(s) is(are) located \n"
               "    -t         The path to save file(s)                   \n"
               "    -e         Encrypt file(s)                            \n"
               "    -d         Decrypt file(s)                            \n"
               "    -h         Show help message                          \n\n");
        exit(EXIT_SUCCESS);
    }

    if ((arg_bit >> 2) & 1) { // argument -t
        tmp_count = 0;
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-t")) {
                ++i;
                if (i == argc) {
                    fprintf(stderr, "No destination path\n"
                                    "Use argument -h for more details\n\n");
                    exit(EXIT_FAILURE);
                }
                dest_path = malloc(sizeof(char) * (strlen(argv[i]) + 1));
                MEM_FAILED(dest_path);
                while ((dest_path[tmp_count] = argv[i][tmp_count]))
                    tmp_count++;

                break;
            }
        }
        arg_bit ^= 4;
        flag_dest_path = 1;
    }

    if ((arg_bit >> 3) & 1) { // argument -e
        if ((arg_bit >> 4) & 1) {
            printf("Choose only one key: -e/-d\n");
            goto end;
        }
        arg_bit ^= 8;
        flag_encrypt = 1;
    }

    if ((arg_bit >> 4) & 1) { // argument -d
        arg_bit ^= 16;
        flag_decrypt = 1;
    }

    if (!flag_decrypt && !flag_encrypt) {
        printf("\nYou didn't write what u wanna do\nDo u want encrypt/decrypt?\n"
               "write e/d: ");
        tmp_ch = getchar();
        if (tmp_ch == (int)'e')
            flag_encrypt = 1;
        else if (tmp_ch == (int)'d')
            flag_decrypt = 1;
        else {
            fprintf(stderr, "You didn't choose something\n");
            goto end;
        }
        fun_fflush_stdin();
    }

    cur_path = get_cur_path_al();

    if (arg_bit == 0) { // didn't use keys -a/-p, that means only inputed files
        src_path = get_cur_path_al();
        input_file_count = get_input_file(argc, input_file, argv);
    } else if ((arg_bit >> 1) & 1) { // argument -p
        tmp_count = 0;
        for (int i = 0; i < argc; i++) {
            if (!strcmp(argv[i], "-p")) {
                ++i;
                if (i == argc) {
                    fprintf(stderr, "No source path\n"
                                    "Use argument -h for full details\n\n");
                    exit(EXIT_FAILURE);
                }
                src_path = malloc(sizeof(char) * (strlen(argv[i])+ 1));
                MEM_FAILED(src_path);
                while ((src_path[tmp_count] = argv[i][tmp_count]))
                    tmp_count++;

                break;
            }
        }
        flag_src_path = 1;
        if (!(arg_bit & 1)) // there is no argument -a
            input_file_count = get_input_file(argc, input_file, argv);
        else
            entry_file_count = file_count_in_dir(src_path, entry);
    } else if (arg_bit & 1) { // there is argument -a
        src_path = get_cur_path_al();
        entry_file_count = file_count_in_dir(src_path, entry);
    } else {
        printf("Incorrect input\n");
        goto end;
    }

    if (flag_decrypt || flag_encrypt) {
        if (flag_decrypt)
            goto decrypt;
        else
            goto encrypt;
    } else {
        printf("Incorrect input\n");
        goto end;
    }


encrypt:

    tm = get_cur_date();
    tmp_ptr = create_dir_al(1, dest_path, tm);
    free(dest_path);
    dest_path = tmp_ptr;
    paths_output(src_path, dest_path, cur_path, flag_src_path, flag_dest_path);

    if (arg_bit == 1 || arg_bit == 3) {
        if (entry_file_count) {
            printf("FILE(S) FOR ENCRYPTING:\n\n");
            for (int i = 0; i < entry_file_count; i++)
                printf("%s\n", entry[i]->d_name);
            printf("\n");
        } else {
            printf("\nThere are no files for encrypting\n");
            goto end;
        }
    } else if (arg_bit == 0 || arg_bit == 2) {
        if (input_file_count) {
            printf("FILE(S) FOR ENCRYPTING:\n\n");
            for (int i = 0; i < input_file_count; i++)
                printf("%s\n", input_file[i]);
            printf("\n");
        } else {
            printf("\nThere are no files for encrypting\n");
            goto end;
        }
    } else {
        printf("\nThere is an error\n");
        exit(EXIT_FAILURE);
    }


    printf("%50s", "Input the key for ecnryption: ");
    key_len = get_key(key);

    if (arg_bit == 1 || arg_bit == 3) {
        for (int i = 0; i < entry_file_count; i++) {
            if (search_enc_ext(entry[i]->d_name)) {
                alr_enc_file[alr_enc_file_count] =
                        malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                MEM_FAILED(alr_enc_file[alr_enc_file_count]);
                strncpy(alr_enc_file[alr_enc_file_count],
                        entry[i]->d_name,
                        strlen(entry[i]->d_name));
                alr_enc_file[alr_enc_file_count]
                        [strlen(entry[i]->d_name)] = '\0';
                alr_enc_file_count++;
                continue;
            }
            if (flag_src_path) { // there is argument -p
                new_file_name = cat_src_path_al(entry[i]->d_name, src_path);
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(new_file_name, sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], entry[i]->d_name, strlen(entry[i]->d_name));
                    folder[folder_count][strlen(entry[i]->d_name)] = '\0';
                    folder_count++;
                    free(new_file_name);
                    free(sb);
                    continue;
                } else free(sb);
            } else if (!flag_src_path) { // there is no argument -p
                new_file_name = entry[i]->d_name;
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(entry[i]->d_name, sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], entry[i]->d_name, strlen(entry[i]->d_name));
                    folder[folder_count][strlen(entry[i]->d_name)] = '\0';
                    folder_count++;
                    free(sb);
                    continue;
                } else free(sb);
            }
            if ((fp = fopen(new_file_name, "r")) == NULL) {
                fprintf(stderr, "Can't open file \"%s\"\n", new_file_name);
                fprintf(stderr, "Thus your file \"%s\" will not encrypt\n", entry[i]->d_name);
                not_open_file[not_open_file_count] =
                        malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                MEM_FAILED(not_open_file[not_open_file_count]);
                strncpy(not_open_file[not_open_file_count], entry[i]->d_name,
                        strlen(entry[i]->d_name));
                not_open_file[not_open_file_count][strlen(entry[i]->d_name)] = '\0';
                not_open_file_count++;
                if (flag_src_path)
                    free(new_file_name);
            } else {
                file_len = get_file_length(new_file_name);
                if (flag_src_path)
                    free(new_file_name);
                printf("\nFile \"%s\" is ready for encryption\n", entry[i]->d_name);
                printf("Length of file is - %lld\n", file_len);
                file_data = malloc(((unsigned long)file_len) * sizeof(char));
                MEM_FAILED(file_data);
                get_file_data(fp, file_data, file_len);
                fclose(fp);
                new_file_name = enc_ext_add_al(entry[i]->d_name);
                tmp_ptr = cat_path_al(new_file_name, dest_path);
                free(new_file_name);
                new_file_name = tmp_ptr;
                tmp_ptr = create_name_enc_al(new_file_name);
                free(new_file_name);
                new_file_name = tmp_ptr;
                if ((new_fp = fopen(new_file_name, "w")) == NULL) {
                    fprintf(stderr, "Can't create and open file \"%s\"\n", new_file_name);
                    fprintf(stderr, "Thus your file \"%s\" will not encrypt\n", entry[i]->d_name);
                    not_open_file[not_open_file_count] =
                            malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(not_open_file[not_open_file_count]);
                    strncpy(not_open_file[not_open_file_count], entry[i]->d_name,
                            strlen(entry[i]->d_name));
                    not_open_file[not_open_file_count][strlen(entry[i]->d_name)] = '\0';
                    not_open_file_count++;
                    free(new_file_name);
                    free(file_data);
                    continue;
                }
                make_enc_dec(new_fp, file_len, key_len, file_data, key);
                printf("File \"%s\" was encrypted\n", entry[i]->d_name);
                extension = get_file_ext_al(entry[i]->d_name);
                file_len = add_ext_to_file(new_fp, extension, file_len);
                add_msg_to_file(new_fp, file_len);
                fclose(new_fp);
                free(file_data);
                free(new_file_name);
                free(extension);
            }
        }
    } else if (arg_bit == 0 || arg_bit == 2) {
        for (int i = 0; i < input_file_count; i++) {
            if (search_enc_ext(input_file[i])) {
                alr_enc_file[alr_enc_file_count] =
                        malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                MEM_FAILED(alr_enc_file[alr_enc_file_count]);
                strncpy(alr_enc_file[alr_enc_file_count],
                        input_file[i],
                        strlen(input_file[i]));
                alr_enc_file[alr_enc_file_count]
                        [strlen(input_file[i])] = '\0';
                alr_enc_file_count++;
                continue;
            }
            if (flag_src_path) {
                new_file_name = cat_src_path_al(input_file[i], src_path);
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(new_file_name, sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], input_file[i], strlen(input_file[i]));
                    folder[folder_count][strlen(input_file[i])] = '\0';
                    folder_count++;
                    free(new_file_name);
                    free(sb);
                    continue;
                } else free(sb);
            } else if (!flag_src_path) {
                new_file_name = input_file[i];
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(input_file[i], sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], input_file[i], strlen(input_file[i]));
                    folder[folder_count][strlen(input_file[i])] = '\0';
                    folder_count++;
                    free(sb);
                    continue;
                } else free(sb);
            }
            if ((fp = fopen(new_file_name, "r")) == NULL) {
                fprintf(stderr, "Can't open file \"%s\"\n", new_file_name);
                fprintf(stderr, "Thus your file \"%s\" will not encrypt\n", input_file[i]);
                not_open_file[not_open_file_count] =
                        malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                MEM_FAILED(not_open_file[not_open_file_count]);
                strncpy(not_open_file[not_open_file_count], input_file[i],
                        strlen(input_file[i]));
                not_open_file[not_open_file_count][strlen(input_file[i])] = '\0';
                not_open_file_count++;
                if (flag_src_path)
                    free(new_file_name);
            } else {
                file_len = get_file_length(new_file_name);
                if (flag_src_path)
                    free(new_file_name);
                printf("\nFile \"%s\" is ready for encryption\n", input_file[i]);
                printf("Length of file is - %lld\n", file_len);
                file_data = malloc(((unsigned long)file_len) * sizeof(char));
                MEM_FAILED(file_data);
                get_file_data(fp, file_data, file_len);
                fclose(fp);
                new_file_name = enc_ext_add_al(input_file[i]);
                tmp_ptr = cat_path_al(new_file_name, dest_path);
                free(new_file_name);
                new_file_name = tmp_ptr;
                tmp_ptr = create_name_enc_al(new_file_name);
                free(new_file_name);
                new_file_name = tmp_ptr;
                if ((new_fp = fopen(new_file_name, "w")) == NULL) {
                    fprintf(stderr, "Can't create and open file \"%s\"\n", new_file_name);
                    fprintf(stderr, "Thus your file \"%s\" will not encrypt\n", input_file[i]);
                    not_open_file[not_open_file_count] =
                            malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(not_open_file[not_open_file_count]);
                    strncpy(not_open_file[not_open_file_count], input_file[i],
                            strlen(input_file[i]));
                    not_open_file[not_open_file_count][strlen(input_file[i])] = '\0';
                    not_open_file_count++;
                    free(new_file_name);
                    free(file_data);
                    continue;
                }
                make_enc_dec(new_fp, file_len, key_len, file_data, key);
                printf("File \"%s\" was encrypted\n", input_file[i]);
                extension = get_file_ext_al(input_file[i]);
                file_len = add_ext_to_file(new_fp, extension, file_len);
                add_msg_to_file(new_fp, file_len);
                fclose(new_fp);
                free(file_data);
                free(new_file_name);
                free(extension);
            }
        }
    } else {
        printf("There is an error\nTry later\n");
        exit(EXIT_FAILURE);
    }

    // if there were already encrypted files
    if (alr_enc_file_count) {
        printf("\n\nThis files were already encrypted:\n\n");
        for (int i = 0; i < alr_enc_file_count; i++)
            printf("%s\n", alr_enc_file[i]);
    }

    goto end;


decrypt:

    tm = get_cur_date();
    tmp_ptr = create_dir_al(2, dest_path, tm);
    free(dest_path);
    dest_path = tmp_ptr;
    paths_output(src_path, dest_path, cur_path, flag_src_path, flag_dest_path);

    if (arg_bit == 1 || arg_bit == 3) {
        if (entry_file_count) {
            printf("FILE(S) FOR DECRYPTING:\n\n");
            for (int i = 0; i < entry_file_count; i++)
                printf("%s\n", entry[i]->d_name);
            printf("\n");
        } else {
            printf("\nThere are no files for decrypting\n");
            goto end;
        }

    } else if (arg_bit == 0 || arg_bit == 2) {
        if (input_file_count) {
            printf("FILE(S) FOR DECRYPTING:\n\n");
            for (int i = 0; i < input_file_count; i++)
                printf("%s\n", input_file[i]);
            printf("\n");
        } else {
            printf("\nThere are no files for decrypting\n");
            goto end;
        }
    } else {
        printf("\nThere is an error\n");
        exit(EXIT_FAILURE);
    }


    printf("%50s", "Input the key for decryption: ");
    key_len = get_key(key);

    if (arg_bit == 1 || arg_bit == 3) {
        for (int i = 0; i < entry_file_count; i++) {
            if (!search_enc_ext(entry[i]->d_name)) {
                not_enc_file[not_enc_file_count] =
                        malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                MEM_FAILED(not_enc_file[not_enc_file_count]);
                strncpy(not_enc_file[not_enc_file_count], entry[i]->d_name,
                        strlen(entry[i]->d_name));
                not_enc_file[not_enc_file_count][strlen(entry[i]->d_name)] = '\0';
                not_enc_file_count++;
                continue;
            }
            if (flag_src_path) { // there is argument -p
                new_file_name = cat_src_path_al(entry[i]->d_name, src_path);
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(new_file_name, sb) && S_ISDIR(sb->st_mode)){
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], entry[i]->d_name, strlen(entry[i]->d_name));
                    folder[folder_count][strlen(entry[i]->d_name)] = '\0';
                    folder_count++;
                    free(new_file_name);
                    free(sb);
                    continue;
                } else free(sb);
            } else if (!flag_src_path) { // there is no argument -p
                new_file_name = entry[i]->d_name;
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(entry[i]->d_name, sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], entry[i]->d_name, strlen(entry[i]->d_name));
                    folder[folder_count][strlen(entry[i]->d_name)] = '\0';
                    folder_count++;
                    free(sb);
                    continue;
                } else free(sb);
            }
            if ((fp = fopen(new_file_name, "r")) == NULL) {
                fprintf(stderr, "Can't open file \"%s\"\n", new_file_name);
                fprintf(stderr, "Thus your file \"%s\" will not decrypt\n", entry[i]->d_name);
                not_open_file[not_open_file_count] =
                        malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                MEM_FAILED(not_open_file[not_open_file_count]);
                strncpy(not_open_file[not_open_file_count], entry[i]->d_name,
                        strlen(entry[i]->d_name));
                not_open_file[not_open_file_count][strlen(entry[i]->d_name)] = '\0';
                not_open_file_count++;
                if (flag_src_path)
                    free(new_file_name);
            } else {
                file_len = get_file_length(new_file_name);
                if (flag_src_path)
                    free(new_file_name);
                file_len = check_msg(fp, file_len);
                if (file_len < 0) {
                    not_enc_file[not_enc_file_count] =
                            malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(not_enc_file[not_enc_file_count]);
                    strncpy(not_enc_file[not_enc_file_count], entry[i]->d_name,
                            strlen(entry[i]->d_name));
                    not_enc_file[not_enc_file_count][strlen(entry[i]->d_name)] = '\0';
                    not_enc_file_count++;
                    continue;
                }
                extension = get_ext_inside_file_al(fp, file_len);
                if (extension == NULL)
                    file_len -= 1; // minus special number
                else
                    file_len = file_len - (long long)strlen(extension) - 1;
                printf("\nFile \"%s\" is ready for decryption\n", entry[i]->d_name);
                printf("Length of file is - %lld\n", file_len);
                file_data = malloc(((unsigned long)file_len) * sizeof(char));
                MEM_FAILED(file_data);
                get_file_data(fp, file_data, file_len);
                fclose(fp);
                new_file_name = enc_ext_del_al(entry[i]->d_name);
                tmp_ptr = cat_path_al(new_file_name, dest_path);
                free(new_file_name);
                new_file_name = tmp_ptr;
                tmp_ptr = create_name_dec_al(new_file_name, extension);
                free(new_file_name);
                new_file_name = tmp_ptr;
                if ((new_fp = fopen(new_file_name, "w")) == NULL) {
                    fprintf(stderr, "Can't create and open file \"%s\"\n", new_file_name);
                    fprintf(stderr, "Thus your file \"%s\" will not decrypt\n", entry[i]->d_name);
                    not_open_file[not_open_file_count] =
                            malloc(sizeof(char) * (strlen(entry[i]->d_name) + 1));
                    MEM_FAILED(not_open_file[not_open_file_count]);
                    strncpy(not_open_file[not_open_file_count], entry[i]->d_name,
                            strlen(entry[i]->d_name));
                    not_open_file[not_open_file_count][strlen(entry[i]->d_name)] = '\0';
                    not_open_file_count++;
                    free(new_file_name);
                    free(file_data);
                    if (extension != NULL)
                        free(extension);
                    continue;
                }
                make_enc_dec(new_fp, file_len, key_len, file_data, key);
                printf("File \"%s\" was decrypted\n", entry[i]->d_name);
                free(file_data);
                free(new_file_name);
                if (extension != NULL)
                    free(extension);
            }
        }
    } else if (arg_bit == 0 || arg_bit == 2) {
        for (int i = 0; i < input_file_count; i++) {
            if (!search_enc_ext(input_file[i])) {
                not_enc_file[not_enc_file_count] =
                        malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                MEM_FAILED(not_enc_file[not_enc_file_count]);
                strncpy(not_enc_file[not_enc_file_count], input_file[i],
                        strlen(input_file[i]));
                not_enc_file[not_enc_file_count][strlen(input_file[i])] = '\0';
                not_enc_file_count++;
                continue;
            }
            if (flag_src_path) {
                new_file_name = cat_src_path_al(input_file[i], src_path);
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(new_file_name, sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], input_file[i], strlen(input_file[i]));
                    folder[folder_count][strlen(input_file[i])] = '\0';
                    folder_count++;
                    free(new_file_name);
                    free(sb);
                    continue;
                } else free(sb);
            } else if (!flag_src_path) {
                new_file_name = input_file[i];
                sb = malloc(sizeof(struct stat));
                MEM_FAILED(sb);
                if (!stat(input_file[i], sb) && S_ISDIR(sb->st_mode)) {
                    // it is a folder
                    folder[folder_count] = malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(folder[folder_count]);
                    strncpy(folder[folder_count], input_file[i], strlen(input_file[i]));
                    folder[folder_count][strlen(input_file[i])] = '\0';
                    folder_count++;
                    free(sb);
                    continue;
                } else free(sb);
            }
            if ((fp = fopen(new_file_name, "r")) == NULL) {
                fprintf(stderr, "Can't open file \"%s\"\n", new_file_name);
                fprintf(stderr, "Thus your file \"%s\" will not decrypt\n", input_file[i]);
                not_open_file[not_open_file_count] =
                        malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                MEM_FAILED(not_open_file[not_open_file_count]);
                strncpy(not_open_file[not_open_file_count], input_file[i],
                        strlen(input_file[i]));
                not_open_file[not_open_file_count][strlen(input_file[i])] = '\0';
                not_open_file_count++;
                if (flag_src_path)
                    free(new_file_name);
            } else {
                file_len = get_file_length(new_file_name);
                if (flag_src_path)
                    free(new_file_name);
                file_len = check_msg(fp, file_len);
                if (file_len < 0) {
                    not_enc_file[not_enc_file_count] =
                            malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(not_enc_file[not_enc_file_count]);
                    strncpy(not_enc_file[not_enc_file_count], input_file[i],
                            strlen(input_file[i]));
                    not_enc_file[not_enc_file_count][strlen(input_file[i])] = '\0';
                    not_enc_file_count++;
                    continue;
                }
                extension = get_ext_inside_file_al(fp, file_len);
                if (extension == NULL)
                    file_len -= 1; // minus special number
                else
                    file_len = file_len - (long long)strlen(extension) - 1;
                printf("\nFile \"%s\" is ready for decryption\n", input_file[i]);
                printf("Length of file is - %lld\n", file_len);
                file_data = malloc(((unsigned long)file_len) * sizeof(char));
                MEM_FAILED(file_data);
                get_file_data(fp, file_data, file_len);
                fclose(fp);
                new_file_name = enc_ext_del_al(input_file[i]);
                tmp_ptr = cat_path_al(new_file_name, dest_path);
                free(new_file_name);
                new_file_name = tmp_ptr;
                tmp_ptr = create_name_dec_al(new_file_name, extension);
                free(new_file_name);
                new_file_name = tmp_ptr;
                if ((new_fp = fopen(new_file_name, "w")) == NULL) {
                    fprintf(stderr, "Can't create and open file \"%s\"\n", new_file_name);
                    fprintf(stderr, "Thus your file \"%s\" will not decrypt\n", input_file[i]);
                    not_open_file[not_open_file_count] =
                            malloc(sizeof(char) * (strlen(input_file[i]) + 1));
                    MEM_FAILED(not_open_file[not_open_file_count]);
                    strncpy(not_open_file[not_open_file_count], input_file[i],
                            strlen(input_file[i]));
                    not_open_file[not_open_file_count][strlen(input_file[i])] = '\0';
                    not_open_file_count++;
                    free(new_file_name);
                    free(file_data);
                    if (extension != NULL)
                        free(extension);
                    continue;
                }
                make_enc_dec(new_fp, file_len, key_len, file_data, key);
                printf("File \"%s\" was decrypted\n", input_file[i]);
                free(file_data);
                free(new_file_name);
                if (extension != NULL)
                    free(extension);
            }
        }
    } else {
        printf("There is an error\nTry later\n");
        exit(EXIT_FAILURE);
    }

    // when there were files that weren't encrypted
    if (not_enc_file_count) {
        printf("\n\nThis files were not decrypted, "
               "because this files were not encrypted:\n\n");
        for (int i = 0; i < not_enc_file_count; i++)
            printf("%s\n", not_enc_file[i]);
    }


end:
    // when there were folders that we didn't open
    if (folder_count) {
        printf("\n\nThis folders were not used:\n\n");
        for (int i = 0; i < folder_count; i++)
            printf("%s\n", folder[i]);
    }

    // when there were files that we couldn't open
    if (not_open_file_count) {
        printf("\n\nThis files were not opened:\n\n");
        for (int i = 0; i < not_open_file_count; i++)
            printf("%s\n", not_open_file[i]);
    }

    // free memory
    free(cur_path);
    free(src_path);
    free(dest_path);
    for (int i = 0; i < input_file_count; i++)
        free(input_file[i]);
    for (int i = 0; i < not_enc_file_count; i++)
        free(not_enc_file[i]);
    for (int i = 0; i < alr_enc_file_count; i++)
        free(alr_enc_file[i]);
    for (int i = 0; i < entry_file_count; i++)
        free(entry[i]);
    for (int i = 0; i < not_open_file_count; i++)
        free(not_open_file[i]);
    for (int i = 0; i < folder_count; i++)
        free(folder[i]);

    printf("\n");
    return 0;
}


int search_enc_ext(char *name)
{
    unsigned long length = strlen(name);

    for (unsigned long i = 0; i < length; i++) {
        if (name[i] == ENC_EXTENSION[0]) {
            for (unsigned long j = i + 1, k = 1; j < length; j++, k++) {
                if (name[j] != ENC_EXTENSION[k])
                    break;
                if (j == length - 1 && k == strlen(ENC_EXTENSION) - 1)
                    return 1;
            }
        }
    }

    return 0;
}

int file_count_in_dir(const char *path, struct dirent **new_entry)
{
    struct dirent *entry = NULL;
    DIR *dir;
    int count = 0;

    dir = opendir(path);
    if (dir == NULL) {
        fprintf(stderr, "Can't open path: %s\n", path);
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")
                                        || !strcmp(entry->d_name, PROG_NAME)) // may be del. it
            continue;

        if (count >= NUMBER_OF_FILES) {
            printf("Files are more then %d, I stop process\n", NUMBER_OF_FILES);
            break;
        }
        new_entry[count] = malloc(sizeof(struct dirent));
        MEM_FAILED(new_entry[count]);
        strncpy(new_entry[count]->d_name, entry->d_name, strlen(entry->d_name));
        new_entry[count]->d_name[strlen(entry->d_name)] = '\0';
        count++;
    }
    closedir(dir);
    free(entry);

    return count;
}

char *get_cur_path_al(void)
{
    char *ret_pwd = NULL;
    char *buf = malloc(sizeof(char) * BUF_PATH);
    MEM_FAILED(buf);

    if ((ret_pwd = getcwd(buf, BUF_PATH)) == NULL) {
        if (errno == ERANGE) {
            // buffer is too small. try to malloc more memory
            free(buf);
            buf = malloc(sizeof(char) * (strlen(ret_pwd) + 1));
            MEM_FAILED(buf);
            if (getcwd(buf, strlen(ret_pwd) + 1) == NULL) {
                if (errno == ERANGE) {
                    fprintf(stderr, "Can't get current path due to problems with buffer\n");
                    exit(EXIT_FAILURE);
                }
                fprintf(stderr, "Can't get current path due to problems with dir\n");
                exit(EXIT_FAILURE);
            }
            return buf;
        }
        fprintf(stderr, "Can't get current path due to problems with dir\n");
        exit(EXIT_FAILURE);
    }

    return buf;
}

int get_input_file(int argc, char **input_file, char **argv)
{
    int file_count = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PROG_NAME))
            continue;
        if (!strcmp(argv[i], "-e") || !strcmp(argv[i], "-d"))
            continue; // pass encrypt/decrypt
        if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "-p")) {
            ++i;
            continue; // pass dest/src paths
        }
        if (file_count >= INPUT_FILES_MAX) {
            fprintf(stderr, "You have exceeded limit of inputed files (%d)\n", INPUT_FILES_MAX);
            exit(EXIT_FAILURE);
        }
        input_file[file_count] = malloc(sizeof(char) * (strlen(argv[i]) + 1));
        MEM_FAILED(input_file[file_count]);
        strncpy(input_file[file_count], argv[i], strlen(argv[i]));
        input_file[file_count][strlen(argv[i])] = '\0';
        file_count++;
    }

    return file_count;
}

long long get_file_length(char *name)
{
    struct stat sb;

    if (stat(name, &sb) == -1){
        fprintf(stderr, "Can't get the length of file\n");
        exit(EXIT_FAILURE);
    }

    return sb.st_size;
}

void get_file_data(FILE *fp, char *data, long long file_len)
{
    size_t nr;

    nr = fread(data, sizeof(char), (unsigned long)file_len, fp);
    if (nr != (size_t)file_len) {
        if (ferror(fp))
            fprintf(stderr, "Error in stream\n");
        else
            fprintf(stderr, "Error in fread()\n");

        exit(EXIT_FAILURE);
    }
}

void fun_fflush_stdin(void)
{
    while (getchar() != 10)
        ;
}

unsigned long get_key(char *key)
{
    int i = 0;
    int ch;
    unsigned long key_len = 0;

    while ((ch = getchar()) != 10) {
        key[i++] = (char)ch;
        if (i >= KEY_LENGTH) {
            fprintf(stderr, "Key is too long\n");
            exit(EXIT_FAILURE);
        }
    }
    key[i] = '\0';

    key_len = strlen(key);
    if (key_len == 0) {
        fprintf(stderr, "The key must contain at least one character\n");
        exit(EXIT_FAILURE);
    }

    return key_len;
}

void make_enc_dec(FILE *fp, long long file_len, unsigned long key_len,
                         char *data, char *key)
{
    char *tmp_buf = NULL;
    unsigned long key_i = 0;
    size_t nr;

    tmp_buf = malloc(sizeof(char) * 1);
    MEM_FAILED(tmp_buf);
    for (long long i = 0; i < file_len; i++) {
        *tmp_buf = data[i] ^ key[key_i++];
        nr = fwrite(tmp_buf, sizeof(char), 1, fp);
        if (nr != 1) {
            if (ferror(fp))
                fprintf(stderr, "Error in stream by encryption/decryption\n");
            else
                fprintf(stderr, "Error in fwrite() by encryption/decryption\n");

            exit(EXIT_FAILURE);
        }

        if (key_i == key_len)
            key_i = 0;
    }
    free(tmp_buf);
}

char *cat_path_al(char *old_name, char *path)
{
    char *new_name = NULL;
    int cur_pos = 0;

    // 2 -> '/' + '\0'
    new_name = malloc(sizeof(char) * (strlen(old_name) + strlen(path) + 2));
    MEM_FAILED(new_name);
    while (*path)
        new_name[cur_pos++] = *path++;
    new_name[cur_pos++] = '/';

    while ((new_name[cur_pos++] = *old_name++))
        ;

    return new_name;
}

char *cat_src_path_al(char *old_name, char *path)
{
    char *new_name = NULL;
    int cur_pos = 0;

    // 2 -> '/' + '\0'
    new_name = malloc((strlen(old_name) + strlen(path) + 2) * sizeof(char));
    MEM_FAILED(new_name);
    while (*path)
        new_name[cur_pos++] = *path++;

    if (new_name[cur_pos - 1] != '/')
        new_name[cur_pos++] = '/';

    while ((new_name[cur_pos++] = *old_name++))
        ;

    return new_name;
}

void output_about_program()
{
    printf("#####################################################\n"
           "#                                                   #\n"
           "#      Check file \"README\" for documentation        #\n"
           "#                                                   #\n"
           "#####################################################\n\n\n");
}

long long add_msg_to_file(FILE *fp, long long file_len)
{
    long pos;
    size_t nr;

    fseek(fp, (long)file_len, SEEK_SET);
    pos = ftell(fp);
    if (pos < 0) {
        fprintf(stderr, "Can't get position in file\n");
        exit(EXIT_FAILURE);
    }

    nr = fwrite(END_FILE_MSG, strlen(END_FILE_MSG), 1, fp);
    if (nr != 1) {
        if (ferror(fp))
            fprintf(stderr, "Error in stream\n");
        else
            fprintf(stderr, "Error in fwrite()\n");

        exit(EXIT_FAILURE);
    }
    file_len += (long long)strlen(END_FILE_MSG);
    fseek(fp, 0, SEEK_SET);

    return file_len;
}

long long check_msg(FILE *fp, long long file_len)
{
    /*
     * This function performs two actions:
     * - check file for message in the end
     * - return lenght of file without msg, if file has a message, -1 otherwise
     */

    long pos = -1;
    char *msg_buf = NULL;
    long ret;

    msg_buf = malloc(sizeof(char) * (strlen(END_FILE_MSG) + 1));
    MEM_FAILED(msg_buf);
    fseek(fp, (long)(file_len - (long long)strlen(END_FILE_MSG)), SEEK_SET); // go before msg
    pos = ftell(fp);
    if (pos < 0) {
        fprintf(stderr, "Can't get position in file\n");
        exit(EXIT_FAILURE);
    }

    fread(msg_buf, strlen(END_FILE_MSG), 1, fp);
    msg_buf[strlen(END_FILE_MSG)] = '\0';
    fseek(fp, 0, SEEK_SET);
    ret = (!strcmp(msg_buf, END_FILE_MSG)) ? pos : -1; // if equal then return lenght of file
    free(msg_buf);

    return (long long)ret;
}

char *enc_ext_del_al(char *name)
{
    char *new_name = NULL;
    char dot = '.'; // will search it
    int last_entry = -1;

    for (unsigned long i = 0; i < strlen(name); i++)
        if (name[i] == dot)
            last_entry = (int)i;

    if (last_entry < 0) {
        fprintf(stderr, "Can't find dot in encrypted file name\n");
        exit(EXIT_FAILURE);
    }

    new_name = malloc(sizeof(char) * ((unsigned long)last_entry + 1));
    MEM_FAILED(new_name);
    for (int i = 0; i < last_entry; i++)
        new_name[i] = name[i];
    new_name[last_entry] = '\0';

    return  new_name;
}

char *enc_ext_add_al(char *name)
{
    char *new_name = NULL;
    char dot = '.';
    unsigned long j;
    int last_entry = -1;

    for (unsigned long i = 0; i < strlen(name); i++)
        if (name[i] == dot)
            last_entry = (int)i;

    // if there is no dot in file name
    if (last_entry == -1) {
        new_name = malloc(sizeof(char) * (strlen(name) + strlen(ENC_EXTENSION) + 1));
        MEM_FAILED(new_name);
        // copy file name
        for (unsigned long i = 0; i < strlen(name); i++)
            new_name[i] = name[i];

        // copy encryption extension (EXTENSION)
        for (unsigned long i = strlen(name), j = 0; j < strlen(ENC_EXTENSION); i++, j++)
            new_name[i] = ENC_EXTENSION[j];
        new_name[strlen(name) + strlen(ENC_EXTENSION)] = '\0';

        return new_name;
    }

    new_name = malloc(sizeof(char) * ((unsigned long)last_entry + strlen(ENC_EXTENSION) +1));
    MEM_FAILED(new_name);
    // copy file name without previous extension
    for (int i = 0; i < last_entry; i++)
        new_name[i] = name[i];

    // copy encryption extension (EXTENSION)
    j = 0;
    for (int i = last_entry; j < strlen(ENC_EXTENSION); i++, j++)
        new_name[i] = ENC_EXTENSION[j];
    new_name[last_entry + (int)strlen(ENC_EXTENSION)] = '\0';

    return  new_name;
}

char *create_name_dec_al(char *name, char *ext)
{
    /*
     * When file can be opened it means that this file exist.
     * In that case file name must contain string "(copyN)",
     * where N - count of copy.
     */

    FILE *fp;
    char str[] = "(copy";
    unsigned long str_len;
    unsigned long ext_len;
    int max_num = 9999;
    char *new_name = NULL;
    unsigned long cur_pos;


    ext_len = (ext == NULL) ? 0 : strlen(ext);
    if (!ext_len) {
        if ((fp = fopen(name, "r")) == NULL) {
            new_name = malloc(sizeof(char) * (strlen(name) + 1));
            MEM_FAILED(new_name);
            cur_pos = 0;
            while ((new_name[cur_pos++] = *name++))
                ;
            return new_name; // file doesn't exist
        }
        fclose(fp);
        goto full;
    }

    new_name = malloc(sizeof(char) * (strlen(name) + ext_len + 1));
    MEM_FAILED(new_name);
    cur_pos = 0;
    for (unsigned long i = 0; i < strlen(name); ++i, cur_pos = i)
        new_name[i] = name[i];

    for (unsigned long i = cur_pos, j = 0; j < ext_len; ++i, cur_pos = i, j++)
        new_name[i] = ext[j];
    new_name[cur_pos] = '\0';

    if ((fp = fopen(new_name, "r")) == NULL)
        return new_name;

    fclose(fp);
    free(new_name);

full:
    str_len = strlen(str);
    // strlen(name) + strlen(str) + strlen(ext) + count of copy(1 - 9999) + ')' + '\0'
    new_name = malloc(sizeof(char) * (strlen(name) + str_len + ext_len + 6));
    MEM_FAILED(new_name);

    cur_pos = 0;
    while (*name)
        new_name[cur_pos++] = *name++;

    for (unsigned long i = cur_pos, j = 0; j < str_len; ++i, cur_pos = i, j++)
        new_name[i] = str[j];

    for (int i = 1; i <= max_num; i++) {
        if (ext_len)
            sprintf(&new_name[cur_pos], "%d)%s", i, ext);
        else
            sprintf(&new_name[cur_pos], "%d)", i);

        if ((fp = fopen(new_name, "r")) == NULL)
            return new_name;
        fclose(fp);
    }

    fprintf(stderr, "Can't create decrypted file name\n");
    exit(EXIT_FAILURE);
}

char *create_name_enc_al(char *name)
{
    /*
     * When file can be opened it means that this file exist.
     * In that case file name must contain string "(copyN)",
     * where N - count of copy.
     */

    FILE *fp;
    char *new_name = NULL;
    char dot = '.';
    char str[] = "(copy";
    unsigned long str_len;
    unsigned long cur_pos;
    unsigned long tmp_len;
    int max_num = 9999;
    int last_entry = -1;


    if ((fp = fopen(name, "r")) == NULL) {
        new_name = malloc(sizeof(char) * (strlen(name) + 1));
        MEM_FAILED(new_name);
        cur_pos = 0;
        while ((new_name[cur_pos++] = *name++))
            ;
        return new_name; // file doesn't exist
    }
    fclose(fp);

    // try to find extension in file name
    for (unsigned long i = 0; i < strlen(name); i++)
        if (name[i] == dot)
            last_entry = (int)i;

    // don't really need it, but all is possible
    if (last_entry < 0) {
        fprintf(stderr, "Something went wrong while creating encrypted file name\n");
        exit(EXIT_FAILURE);
    }

    str_len = strlen(str);
    // strlen(name) + strlen(str) + count of copy(1 - 9999) + ')' + '\0'
    new_name = malloc(sizeof(char) * (strlen(name) + str_len + 6));
    MEM_FAILED(new_name);

    cur_pos = 0;
    for (int i = 0; i < last_entry; ++i, cur_pos = (unsigned long)i)
        new_name[i] = name[i];

    for (unsigned long i = cur_pos, j = 0; j < str_len; ++i, cur_pos = i, j++)
        new_name[i] = str[j];

    for (int i = 1, j = 0; i <= max_num; i++, j = 0) {
        sprintf(&new_name[cur_pos], "%d)", i);
        tmp_len = strlen(new_name);
        while ((new_name[tmp_len++] = ENC_EXTENSION[j++]))
            ;
        if ((fp = fopen(new_name, "r")) == NULL)
            return new_name;
        fclose(fp);
    }

    fprintf(stderr, "Can't create encrypted file name\n");
    exit(EXIT_FAILURE);
}

char *create_dir_al(int choice, char *path, struct tm tm)
{
    char *dir = NULL;
    int dir_ret = -1;
    unsigned long cur_pos;
    unsigned long path_len;


    path_len = (path == NULL) ? 0 : strlen(path);
    // 17 -> '/' (after path if not NULL) + yyyymmdd_hhmmss + '\0'
    if (choice == 1)
        dir = malloc(sizeof(char) * (path_len + strlen(ENC_DIR) + 17));
    else
        dir = malloc(sizeof(char) * (path_len + strlen(DEC_DIR) + 17));
    MEM_FAILED(dir);

    cur_pos = 0;
    if (path_len) {
        for (unsigned long i = 0; i < path_len; ++i, cur_pos = i)
            dir[i] = path[i];

        if (path[path_len - 1] != '/')
            dir[cur_pos++] = '/';
    }

    if (choice == 1) {
        for (unsigned long i = cur_pos, j = 0; j < strlen(ENC_DIR); ++i, j++, cur_pos = i)
            dir[i] = ENC_DIR[j];

        sprintf(&dir[cur_pos], "%d%d%d_%d%d%d", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
        for (unsigned long i = cur_pos, j = 0; j < strlen(DEC_DIR); ++i, j++, cur_pos = i)
            dir[i] = DEC_DIR[j];

        sprintf(&dir[cur_pos], "%d%d%d_%d%d%d", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    errno = 0;
    dir_ret = mkdir(dir, 0755);
    if (dir_ret != 0) {
        if (errno == EEXIST)
            fprintf(stderr, "Dir %s is already exist\n", dir);
        else
            fprintf(stderr, "Can't create dir\n");

        exit(EXIT_FAILURE);
    }

    return dir;
}

struct tm get_cur_date(void)
{
    time_t t = time(NULL);
    struct tm tm;

    return tm = *localtime(&t);
}

void paths_output(char *src_path, char *dest_path, char *cur_path, int flag_src_path,
                            int flag_dest_path)
{
    printf("--------------------------------------------------------------------------------\n");
    if (flag_dest_path)
        printf("DEST PATH: %s\n", dest_path);
    else
        printf("DEST PATH: %s/%s\n", cur_path, dest_path);
    printf("--------------------------------------------------------------------------------\n");

    printf("--------------------------------------------------------------------------------\n");
    if (flag_src_path)
        printf("SRC PATH: %s\n", src_path);
    else
        printf("SRC PATH: %s\n", cur_path);
    printf("--------------------------------------------------------------------------------\n\n");
}

long long add_ext_to_file(FILE *fp, char *ext, long long file_len)
{
    long pos;
    size_t nr;

    fseek(fp, (long)file_len, SEEK_SET);
    pos = ftell(fp);
    if (pos < 0) {
        fprintf(stderr, "Can't get position in file\n");
        exit(EXIT_FAILURE);
    }

    nr = fwrite(ext, strlen(ext), 1, fp);
    if (nr != 1) {
        if (ferror(fp))
            fprintf(stderr, "Error in stream\n");
        else
            fprintf(stderr, "Error in fwrite()\n");

        exit(EXIT_FAILURE);
    }
    file_len += (long long)strlen(ext);
    fseek(fp, 0, SEEK_SET);

    return file_len;
}

char *get_file_ext_al(char *name)
{
    char *ext = NULL;
    char magic_num = MAGIC_NUMBER;
    char dot = '.';
    unsigned long len = strlen(name);
    int last_entry = -1;


    for (unsigned long i = 0; i < len; i++)
        if (name[i] == dot)
            last_entry = (int)i;

    // there is no extension in file name
    if (last_entry < 0) {
        ext = malloc(sizeof(char) * 2); // magic number(1) + \0
        MEM_FAILED(ext);
        ext[0] = magic_num;
        ext[1] = '\0';
        return ext;
    }

    // \0 + magic number
    ext = malloc(sizeof(char) * (len - (unsigned long)last_entry + 2));
    MEM_FAILED(ext);
    ext[0] = magic_num;
    for (unsigned long i = (unsigned long)last_entry, j = 1; i < len; i++, j++)
        ext[j] = name[i];
    ext[len - (unsigned long)last_entry + 1] = '\0';

    return ext;
}

char *get_ext_inside_file_al(FILE *fp, long long file_len)
{
    /*
     * This function will be called after function which
     * will delete the msg from file. When we encrypt
     * we add at first previous extension of file and
     * only then msg to the end. We have such situation
     * -> ..file content...MagicnumberExtensionNaNgrata
     * By decryption we must at first delete msg from file
     * and then we can get extension. But we can't delete
     * smth from file thus we just truncate the length
     * of file. At tis function file length is already
     * truncated.
     */

    char *ext = NULL;
    int ch;
    unsigned long ext_len = 0;

    fseek(fp, (long)file_len - 1, SEEK_SET);
    for (; ;) {
        ch = fgetc(fp);
        if (ch == MAGIC_NUMBER)
            break;
        fseek(fp, -2, SEEK_CUR); // go back on 1 symbol
        ext_len++;
    }

    if (ext_len == 0) { // there is no extension
        fseek(fp, 0, SEEK_SET);
        return NULL;
    }

    ext = malloc(sizeof(char) * (ext_len + 1));
    MEM_FAILED(ext);
    fseek(fp, (long)(file_len - (long long)ext_len), SEEK_SET);
    fread(ext, ext_len, 1, fp);
    ext[ext_len] = '\0';
    fseek(fp, 0, SEEK_SET);

    return ext;
}



