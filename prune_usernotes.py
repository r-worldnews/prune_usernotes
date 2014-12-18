import sys, os
import logging, logging.config
import praw
import json

from ConfigParser import SafeConfigParser
from datetime import datetime
from requests.exceptions import HTTPError

MAX_PAGE_SIZE = 290500

cfg_file = SafeConfigParser()
path_to_cfg = os.path.abspath(os.path.dirname(sys.argv[0]))
path_to_cfg = os.path.join(path_to_cfg, 'usernotes.cfg')
cfg_file.read(path_to_cfg)
logging.config.fileConfig(path_to_cfg)


def check_user_inactive(username, cutoff_days):
    try:
        logging.debug('checking if /u/{0} with very old ban note is inactive'.format(username))
        redditor = r.get_redditor(username)
        for post in redditor.get_overview(limit=1):
            age_of_last_contribution = datetime.now() - datetime.fromtimestamp(post.created)
            if age_of_last_contribution.days > cutoff_days:
                logging.info('pruned very old ban note for /u/{0}, did not post for {1} days'
                    .format(username, age_of_last_contribution.days))
                return True

    except HTTPError as e:
        if e.response.status_code == 404:
            logging.info('pruned very old ban note for /u/{0}, is shadowbanned: {1}'.format(username, e))
            return True
    return False


def prune_very_old_notes(username, entry, cutoff_days):
    user_notes_after_pruning_very_old_entries = []
    for user_note in entry['ns']:
        datetime_of_usernote = datetime.fromtimestamp(user_note['t'] / 1000)
        age_of_user_note = datetime.now() - datetime_of_usernote
        note_prunable = False
        if age_of_user_note.days > cutoff_days:
            if not 'ban' in user_note['n'].lower():
                logging.info('pruned very old note from {0} for /u/{1}\t{2}'.format(
                    str(datetime_of_usernote), username, user_note['n']))
                note_prunable = True
            else:
                if datetime.now().weekday() == 6:
                    # on Sunday also for inactive users
                    note_prunable = check_user_inactive(username, cutoff_days)

        if not note_prunable:
            user_notes_after_pruning_very_old_entries.append(user_note)

    entry['ns'] = user_notes_after_pruning_very_old_entries


def check_user_prunable(username, entry, cutoff_days):
    user_notes = entry['ns']
    if len(user_notes) == 0:
        logging.info('pruned /u/{0} without any notes'.format(username))
        return True
    elif len(user_notes) == 1:
        only_user_note = user_notes[0]
        datetime_of_only_usernote = datetime.fromtimestamp(only_user_note['t'] / 1000)
        age_of_only_user_note = datetime.now() - datetime_of_only_usernote
        if age_of_only_user_note.days > cutoff_days and not 'ban' in only_user_note['n'].lower():
            logging.info('pruned only user note from {0} for /u/{1}\t{2}'.format(
                str(datetime_of_only_usernote), username, only_user_note['n']))
            return True
    else:
        return False


def check_user_bannable(entry, subreddit_name):
    len_notes = len(entry['ns'])
    if len_notes > 3:
        notes_after_last_ban = []
        notes_by_most_recent_first = sorted(entry['ns'], key=lambda x: x['t'], reverse=True)
        datetime_of_most_recent_user_note = datetime.fromtimestamp(notes_by_most_recent_first[0]['t'] / 1000)
        age_of_most_recent_user_note = datetime.now() - datetime_of_most_recent_user_note

        for user_note in notes_by_most_recent_first:
            if 'banned' in user_note['n'].lower():
                break
            else:
                link_ids = user_note['l'].split(',')
                user_note_text_ascii = user_note['n'].encode('ascii', 'ignore')
                link_start = '[{0}](/r/{1}'.format(user_note_text_ascii, subreddit_name)
                if len(link_ids) == 2 and link_ids[0] == 'm':
                    notes_after_last_ban.append(link_start + '/message/messages/{0})'.format(link_ids[1]))
                if len(link_ids) == 2:
                    notes_after_last_ban.append(link_start + '/comments/{0}/)'.format(link_ids[1]))
                elif len(link_ids) == 3:
                    notes_after_last_ban.append(link_start + '/comments/{0}/x/{1}/)'.format(link_ids[1], link_ids[2]))

        if len(notes_after_last_ban) > 4:
            return notes_after_last_ban
        elif len(notes_after_last_ban) > 3 and age_of_most_recent_user_note.days < 2:
            return notes_after_last_ban
    return None


# global reddit session
r = None


def main():
    global r

    try:
        r = praw.Reddit(user_agent=cfg_file.get('reddit', 'user_agent'))
        r.config.decode_html_entities = True
        access_username = cfg_file.get('reddit', 'username')
        access_password = cfg_file.get('reddit', 'password')
        logging.info('Logging in as {0}'.format(access_username))
        r.login(access_username, access_password)
        logging.debug('Logged in successfully')

        cutoff_days_for_users_with_only_one_note = \
            cfg_file.getint('prune_usernotes', 'cutoff_days_for_users_with_only_one_note')
        cutoff_days_for_all_notes = cfg_file.getint('prune_usernotes', 'cutoff_days_for_all_notes')
        subreddit_name = cfg_file.get('prune_usernotes', 'subreddit_name')
        usernotes_wiki_page = r.get_wiki_page(subreddit_name, 'usernotes')

        logging.info('loading wikipage data')
        json_data = json.loads(usernotes_wiki_page.content_md)
        logging.info('done loading wikipage data')

        users = json_data['users']
        logging.info('users before pruning: {0}'.format(len(users)))
        for username, entry in users.items():
            prune_very_old_notes(username, entry, cutoff_days_for_all_notes)
            if check_user_prunable(username, entry, cutoff_days_for_users_with_only_one_note):
                del users[username]
        logging.info('users after pruning: {0}'.format(len(users)))

        logging.info('writing wikipage data')
        wiki_page_edit_reason = \
            'User notes pruning: notes older than {0} days '.format(cutoff_days_for_all_notes) + \
            'and single note users where note is older than {0} days'.format(cutoff_days_for_users_with_only_one_note)
        json_dump = json.dumps(json_data, separators=(',', ':'))
        r.edit_wiki_page(subreddit_name, 'usernotes', json_dump, wiki_page_edit_reason)
        logging.info('done writing wikipage data')

        logging.info('checking users for possible ban')
        bannable_users = {}
        for username, entry in users.items():
            qualifying_notes = check_user_bannable(entry, subreddit_name)
            if qualifying_notes is not None:
                bannable_users[username] = qualifying_notes
        if len(bannable_users) > 0:
            message = 'The following users might qualify for a ban ' \
                      'or have already been banned and are just missing a \"banned\" usernote:\n\n'
            for user, qualifying_notes in bannable_users.items():
                message = message + '* /u/{0} -> {1} usernotes: {2}\n'.format(user, len(qualifying_notes),
                                                                              qualifying_notes)
            message = message + '\n^(wiki page is currently at {0} characters, {1} percent of page limit)'.format(
                len(json_dump), (len(json_dump) * 100) / MAX_PAGE_SIZE)
            r.send_message('/r/' + subreddit_name, 'Possible candidates for a ban', message)
            logging.info('sent following message for possible bans: {0}'.format(message))
        logging.info('done checking users for possible ban')

    except Exception as e:
        logging.error('ERROR: {0}'.format(e))
    finally:
        logging.info("done.")


if __name__ == '__main__':
    main()
