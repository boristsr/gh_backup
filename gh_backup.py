"""
Backup all repositories and wikis from a specified user of repository.

As this is a backup program, if there are any failures, they will be reported,
but the rest of the backup will be attempted if possible.

You must specify a username and password combination, or a PAT, but not both.

You can specify a user or an organsation to backup, but not both.
"""

import logging
import argparse
import sys
import shutil
from os import path
from enum import Enum


import github
from github import Github
import git
from git import Repo

log = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO)

HELP_DESCRIPTION = """
Backup all repositories and wikis from a specified user of repository.

As this is a backup program, if there are any failures, they will be reported,
but the rest of the backup will be attempted if possible.

You must specify a username and password combination, or a PAT, but not both.

You can specify a user or an organsation to backup, but not both.
"""

parser = argparse.ArgumentParser(description=HELP_DESCRIPTION)
parser.add_argument('-l', '--login', metavar='username', type=str, help='The username to login with')
parser.add_argument('-p', '--password', metavar='password', type=str, help='The password or PAT to login with')
parser.add_argument('--user', metavar='user', type=str, help='The user profile to backup from')
parser.add_argument('--organization', metavar='organization', type=str, help='The organization profile to backup from')
parser.add_argument('-d', '--destination', metavar='destination', type=str, default="", help='The location to output the backup results')
parser.add_argument('-w', '--wikis', action='store_true', help='Adding this flag will enable backup of wikis')
parser.add_argument('-t', '--tickets', action='store_true', help='Adding this flag will enable backup of tickets')

class GitSuccessType(Enum):
    """Different types of git successes or failures"""
    SUCCESS = 0
    FAILED = 1
    DENIED_OR_NOT_EXPORTED = 2

def fetch_lfs_data(local_repo):
    """
    Fetches all lfs data for an existing repository
    """
    git_raw = local_repo.git
    log.info("Fetching LFS data")
    output = git_raw.lfs("fetch", "--all")
    if output.find("error") != -1:
        return False
    return True

def backup_repo(name, url, destination, login, password_or_pat):
    """
    Backup a specific repository to a destination folder. The repo will be stored under (destination)\\(name).git
    name: the name of the repository
    url: the url to backup from
    destination: the top level folder to store a new git folder under
    login: the desired user authentication
    password_or_pat: a password or personal access token valid for this user

    Returns a GithubSuccessType value
    """
    clone_options = ["--quiet", "--mirror"]
    cloned_repo = None
    final_destination = path.join(destination, name + ".git")

    #Try finding and updating existing repo
    repo_exists = False
    log.info("Checking if repo exists in Dest: %s", final_destination)
    if path.exists(final_destination):
        repo_exists = True
        existing_repo_update_failed = False
        log.info("Repo exists, fetching updates: name: %s, URL: %s, Dest: %s", name, url, final_destination)
        #open repo
        cloned_repo = Repo(final_destination)

        #do sanity checks on repo
        if cloned_repo is None:
            existing_repo_update_failed = True
        if cloned_repo.is_dirty():
            existing_repo_update_failed = True
        if cloned_repo.bare is False:
            existing_repo_update_failed = True

        #try updating
        if existing_repo_update_failed is False:
            try:
                for remote in cloned_repo.remotes:
                    remote.fetch()
            except git.exc.GitCommandError as giterror:
                log.error("Git raised error: %s", giterror)
                existing_repo_update_failed = True

        #do sanity checks on repo
        if cloned_repo is None:
            existing_repo_update_failed = True
        if cloned_repo.is_dirty():
            existing_repo_update_failed = True
        if cloned_repo.bare is False:
            existing_repo_update_failed = True

        #if failed, delete existing repo
        if existing_repo_update_failed is True:
            log.info("Failed to fetch updates for existing repo, deleting to start fresh")
            cloned_repo = None
            repo_exists = False
            shutil.rmtree(final_destination)

    #If updating an existing repo failed, then clone to a new repo
    if repo_exists is False:
        log.info("Cloning repo: name: %s, URL: %s, Dest: %s", name, url, final_destination)
        try:
            domain_with_login = f"https://{login}:{password_or_pat}@github.com/"
            url_with_login = url.replace("https://github.com/", domain_with_login)
            cloned_repo = Repo.clone_from(url_with_login, destination, multi_options=clone_options)
        except git.exc.GitCommandError as giterror:
            log.error("Git raised error: %s", giterror)
            if giterror.stderr.find("access denied or repository not exported") != -1:
                return GitSuccessType.DENIED_OR_NOT_EXPORTED
            return GitSuccessType.FAILED

    if cloned_repo is None:
        log.error("Cloned repository is None")
        return GitSuccessType.FAILED

    if cloned_repo.is_dirty():
        log.error("Repository is in a dirty state after clone")
        return GitSuccessType.FAILED

    if cloned_repo:
        lfs_success = fetch_lfs_data(cloned_repo)
        if lfs_success is not True:
            return GitSuccessType.FAILED

    return GitSuccessType.SUCCESS

def backup_wiki_repo(name, url, destination, login, password_or_pat):
    """
    Backup a wiki repository. This does the appropriate adjustments to the URL and name, before calling backup_repo

    name: the name of the repository
    url: the url to backup from
    destination: the top level folder to store a new git folder under
    login: the desired user authentication
    password_or_pat: a password or personal access token valid for this user

    Returns true on success, or false otherwise
    """

    wiki_url = url[:-3] + "wiki.git"
    wiki_name = name + ".wiki"
    log.info("Backup wiki: %s, %s", destination, wiki_url)
    return backup_repo(wiki_name, wiki_url, destination, login, password_or_pat)

def backup_ticket():
    """
    This will backup tickets associated with a repository.
    Not yet implemented
    """

def backup_repos(repos, login, password, src_username: str, destination: str = "", backup_wiki: bool = False, backup_tickets: bool = False):
    """
    Given a list of repositories, this will backup all the repositories available, and if
    desired, their associated wikis and tickets

    repos: an iterable of repositories
    login: the desired user authentication
    password_or_pat: a password or personal access token valid for this user
    src_username: the username that is currently being backed up. Not always specified
    destination: the top level folder to store a new git folder under
    backup_wiki: whether to backup associated wikis or not
    backup_tickets: whether to backup associated tickets or not

    Returns true on success, or false otherwise
    """
    encountered_errors = False
    for repo in repos:
        if repo.owner.login == src_username:
            repo_dest_name = repo.name + ".git"
            repo_dest = path.join(destination, repo_dest_name)
            log.info("Backup repo: %s, %s", repo_dest, repo.clone_url)

            repo_success = backup_repo(repo.name, repo.clone_url, repo_dest, login, password)
            if repo_success is not GitSuccessType.SUCCESS:
                encountered_errors = True

            if repo.has_wiki and backup_wiki:
                wiki_dest_name = repo.name + ".wiki.git"
                wiki_dest = path.join(destination, wiki_dest_name)
                wiki_success = backup_wiki_repo(repo.name, repo.clone_url, wiki_dest, login, password)
                if wiki_success is GitSuccessType.DENIED_OR_NOT_EXPORTED:
                    log.info("Wiki probably doesn't exist. Usually safe to ignore")
                if wiki_success is GitSuccessType.FAILED:
                    encountered_errors = True
                log.info("Backup wiki: %s, %s", repo_dest, repo.clone_url)
            if repo.has_issues and backup_tickets:
                pass
                #log.info("Backup tickets: " + repo.name)
        else:
            log.info("Skipping organisation/member repository: %s", repo.clone_url)

    if encountered_errors:
        return False
    return True

def backup_user(gh_session: Github, login, password, src_username: str, destination: str = "", backup_wiki: bool = False, backup_tickets: bool = False):
    """
    Will list all accessible repositories for a user and back up all found repos.
    Includes special case handling if login and src_username match to also
    backup private repositories

    gh_session: a current Github object, either with a valid set of credentials, or public API
    login: the desired user authentication
    password_or_pat: a password or personal access token valid for this user
    src_username: the username that is currently being backed up
    destination: the top level folder to store a new git folder under
    backup_wiki: whether to backup associated wikis or not
    backup_tickets: whether to backup associated tickets or not

    Returns true on success, or false otherwise
    """
    gh_user = None
    if login == src_username:
        # To get the authenticated user, including private repos, call this method with no parameters
        gh_user = gh_session.get_user()
    else:
        # This will not list private repos
        gh_user = gh_session.get_user(src_username)

    success = backup_repos(gh_user.get_repos(), login, password, src_username, destination, backup_wiki, backup_tickets)
    return success

def backup_organization(gh_session: Github, login, password, src_organization: str, destination: str = "", backup_wiki: bool = False, backup_tickets: bool = False):
    """
    Will list all accessible repositories for an organization and back up all found repos.

    gh_session: a current Github object, either with a valid set of credentials, or public API
    login: the desired user authentication
    password_or_pat: a password or personal access token valid for this user
    src_organization: the organization that is currently being backed up
    destination: the top level folder to store a new git folder under
    backup_wiki: whether to backup associated wikis or not
    backup_tickets: whether to backup associated tickets or not

    Returns true on success, or false otherwise
    """
    gh_org = gh_session.get_organization(src_organization)
    success = backup_repos(gh_org.get_repos(), login, password, src_organization, destination, backup_wiki, backup_tickets)
    return success

def login_to_github(login, password):
    """
    Will attempt to create a Github object with the specified credentials.
    Includes a quick test of the credentials to valid login

    login: the username to login with
    password: a password or PAT associated with the login specified

    returns None if failed to login
    returns a valid Github object otherwise
    """
    gh_session = None

    if login and password:
        gh_session = Github(login, password)
    else:
        log.warning("No login and password combination specified, proceeding with public API. This won't see private repositories and is rate limited.")
        gh_session = Github()

    try:
        # Login doesn't happen until attempting an operation, so try and get the repo this script is from
        gh_session.get_repo("boristsr/gh_backup")
    except github.BadCredentialsException:
        log.error("Failed to login to github, bad credentials")
        gh_session = None
    return gh_session

if __name__ == "__main__":
    args = parser.parse_args()
    if args.user and args.organization:
        log.error("Please specify either a user or an organisation, not both")
        sys.exit(1)

    if not args.user and not args.organization:
        log.error("Please specify either a user or an organisation")
        sys.exit(1)

    new_gh_session = login_to_github(args.login, args.password)

    if new_gh_session is None:
        log.error("Failed to create a github connection")
        sys.exit(1)

    BACKUP_SUCCESS = None

    if args.user:
        try:
            BACKUP_SUCCESS = backup_user(new_gh_session, args.login, args.password, args.user, args.destination, args.wikis, args.tickets)
        except Exception as e:
            log.error("User backup failed: %s", e)
            BACKUP_SUCCESS = False

    if args.organization:
        try:
            BACKUP_SUCCESS = backup_organization(new_gh_session, args.login, args.password, args.organization, args.destination, args.wikis, args.tickets)
        except Exception as e:
            log.error("Organization backup failed: %s", e)
            BACKUP_SUCCESS = False

    if BACKUP_SUCCESS:
        log.info("Backup succeeded!")
        sys.exit(0)
    else:
        log.info("Backup Failed!")
        sys.exit(1)
