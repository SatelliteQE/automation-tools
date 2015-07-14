"""Tools to work with Beaker (https://beaker-project.org/).

The ``bkr`` command-line utility must be available and configured. (Available
via the ``beaker-client`` package on Fedora.) See the `Installing and
configuring the client`_ section of the Beaker documentation.

.. _Installing and configuring the client:
    https://beaker-project.org/docs/user-guide/bkr-client.html#installing-and-configuring-the-client

"""
import pprint
import subprocess
import xml.dom.minidom


def main():
    """Run :func:`beaker_jobid_to_system_info` and print the response."""
    pprint.pprint(beaker_jobid_to_system_info(open('a.xml')))


def _beaker_process_recipe(recipe):
    """Process recipe and return info about it

    :param recipe: recipe (or guestrecipe) element to process

    """
    recipe_info = {}
    res_task = False
    res_tag = False
    recipe_info['id'] = int(recipe.attributes['id'].value)
    recipe_info['system'] = recipe.attributes['system'].value
    recipe_info['arch'] = recipe.attributes['arch'].value
    recipe_info['distro'] = recipe.attributes['distro'].value
    recipe_info['variant'] = recipe.attributes['variant'].value

    # Do we have /distribution/reservesys? If so, status is based on that.
    tasks = recipe.getElementsByTagName('task')
    for task in reversed(tasks):
        if task.attributes['name'].value == '/distribution/reservesys':
            res_task = True
            res_task_element = task
            break

    # Do we have <reservesys>? If so, status is recipe.status.
    reservesyss = recipe.getElementsByTagName('reservesys')
    for _ in reservesyss:
        res_tag = True
        break

    # Determine status of the recipe/system reservation
    if res_tag and not res_task:
        recipe_info['reservation'] = recipe.attributes['status'].value
    elif res_task and not res_tag:
        recipe_info['reservation'] = \
            res_task_element.attributes['status'].value
    elif res_task and res_tag:
        recipe_info['reservation'] = (
            'ERROR: Looks like the recipe for this system have too many '
            'methods to reserve. Do not know what happens.'
        )
    else:
        recipe_info['reservation'] = recipe.attributes['status'].value
    return recipe_info


def beaker_jobid_to_system_info(job_id):
    """Get system reservation task status (plus other info) based on
    Beaker ``job_id``.

    This function requires configured bkr utility. We parse everithing from
    ``bkr job-results [--prettyxml] J:123456``, so if you see some breakage,
    please capture that output.

    For testing putposes, if you provide file descriptor instead of ``job_id``,
    XML will be loaded from there.

    :param job_id: The ID of a Beaker job. For example: 'J:123456'

    """
    systems = []

    # Get XML with job results and create DOM object
    if hasattr(job_id, 'read'):
        dom = xml.dom.minidom.parse(job_id)
    else:
        out = subprocess.check_output(['bkr', 'job-results', job_id])
        dom = xml.dom.minidom.parseString(out)

    # Parse the DOM object. The XML have structure like this (all elements
    # except '<job>' can appear more times):
    #   <job id='123' ...
    #     <recipeSet id='456' ...
    #       <recipe id='789' system='some.system.example.com'
    #         status='Reserved' ...
    #       <recipe id='790' system='another.system.example.com'
    #         status='Completed' ...
    #         <guestrecipe id='147258' ...
    #     </recipeSet>
    #     <recipeSet id='457' ...
    #       ...
    jobs = dom.getElementsByTagName('job')
    for job in jobs:
        recipe_sets = job.getElementsByTagName('recipeSet')
        for recipe_set in recipe_sets:
            recipes = recipe_set.getElementsByTagName('recipe')
            for recipe in recipes:
                systems.append(_beaker_process_recipe(recipe))
                guestrecipes = recipe.getElementsByTagName('guestrecipe')
                for guestrecipe in guestrecipes:
                    systems.append(_beaker_process_recipe(guestrecipe))
    return systems


if __name__ == '__main__':
    main()
