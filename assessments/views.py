import logging
import validators

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views import View
from django.http import JsonResponse, HttpResponseRedirect
from django.contrib import messages
from django.db.models import Avg, Count
from django.db.models.functions import Coalesce
from django.db.models import Q
from django.urls import reverse
from django.db.models import Sum

from assessments.models import Answer, Question, Result, Topic

# Create your views here.

@login_required
def nist(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')

    if request.method == 'GET':
        icons = (
            'mdi-crosshairs-gps',
            'mdi-security',
            'mdi-magnify',
            'mdi-ambulance',
            'mdi-backup-restore'
        )
        ctx = get_assessment_view_data('nist', request.user, icons)
        ctx["assessment_type"] = "nist"

        url = request.get_full_path()
        trailing = '/result'
        ctx["result"] = url[-len(trailing):] == trailing

        return render(request, "assessment.html", ctx)



@login_required
def cyber_essentials(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')

    if request.method == 'GET':
        first_cyber_topic = Topic.objects.filter(assessment_type=1).first()
        first_cyber_question = first_cyber_topic.question_set.first()
        first_cyber_answer = first_cyber_question.answer_set.first()

        icons = (
            'mdi-crosshairs-gps',
            'mdi-security',
            'mdi-magnify',
            'mdi-ambulance',
            'mdi-backup-restore'
        )
        ctx = get_assessment_view_data('cyber', request.user, icons)
        ctx["assessment_type"] = "cyber"
        ctx["first_cyber_anwer_id"] = first_cyber_answer.pk

        url = request.get_full_path()
        trailing = '/result'
        ctx["result"] = url[-len(trailing):] == trailing

        return render(request, "assessment.html", ctx)


def get_user_answers(assessment_type, user):
    assessment_type = int(assessment_type == 'cyber')
    user_answers = (Result.objects.filter(user=user,
                                         answer__question__topic__assessment_type=assessment_type)
                                  .values('answer_id'))

    return tuple(map(lambda ans: ans.get('answer_id'), user_answers))


def get_score(assessment_type, user, user_answers):
    assessment_type = int(assessment_type == 'cyber')
    total_score = (Question.objects.filter(topic__assessment_type=assessment_type)
                                   .aggregate(Sum('max_score'))
                                   .get('max_score__sum'))
                                  
    score = (Answer.objects.filter(pk__in=user_answers)
                          .aggregate(Sum('score'))
                          .get('score__sum'))
    if score is None:
        score = 0

    return round(score * 100 / total_score)



def get_assessment_view_data(assessment_type, user, icons):
    user_answers = get_user_answers(assessment_type, user)
    score = get_score(assessment_type, user, user_answers)
    assessment_type = int(assessment_type == 'cyber')
    topics = list(Topic.objects.filter(assessment_type=assessment_type))
    questions = []

    for topic in topics:
        questions_for_topic = topic.question_set.all()
        recommendation = []
        answers = []

        for q in questions_for_topic:
            ans = []
            rec = True

            for item in q.answer_set.values('id', 'content'):
                checked = item.get('id') in user_answers
                if checked:
                    score = Answer.objects.get(pk=item.get('id')).score
                    if score > 0:
                        rec = False

                ans.append(dict(id=item.get('id'),
                                checked=checked,
                                content=item.get('content')))
            answers.append(ans)
            recommendation.append(rec)
        
        questions.append(list(zip(questions_for_topic, answers, recommendation)))

    return {
        'score': score,
        'has_result': len(user_answers),
        'topics': list(zip(topics, questions, icons))
    }

@login_required
def resources_internal_asessment(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')

    if request.method == 'GET':
        user = request.user
        nist_user_answers = get_user_answers('nist', user)
        nist_score = get_score('nist', user, nist_user_answers)
        cyber_user_answers = get_user_answers('cyber', user)
        cyber_score = get_score('cyber', user, cyber_user_answers)

        ctx = {
            'nist_score': nist_score,
            'cyber_score': cyber_score
        }

        return render(request, "internal_assessment.html", ctx)


@login_required
def do_resources_internal_asessment(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return JsonResponse({}, status=403)
    
    if request.method == 'POST':
        answers = []
        params = {}
        assessment_type = 'nist'

        for key, val in dict(request.POST).items():
            if key == 'csrfmiddlewaretoken':
                pass
            elif key == 'type':
                assessment_type = val[0]
            else:
                params[key] = val

        if assessment_type == 'cyber':
            messages.success(request, 'Recommend', extra_tags='recommend')
        
        redirect_path = 'nist_assessment_result' if assessment_type == 'nist' else 'cyber_essentials_assessment_result'
        assessment_type = int(assessment_type == 'cyber')
        
        (Result.objects.filter(user=request.user,
                               answer__question__topic__assessment_type=assessment_type)).delete()
        
        for key in params:
            answers += params[key]

        results = map(lambda id: Result(answer_id=id, user=request.user), answers)
        Result.objects.bulk_create(results)
    
        return redirect(redirect_path)

    return redirect('internal_assessment')
