from .data import data
import logging


def init(apps, schema_editor):
    Topic = apps.get_model('assessments', 'Topic')
    Question = apps.get_model('assessments', 'Question')
    Answer = apps.get_model('assessments', 'Answer')

    Topic.objects.bulk_create(
        map(lambda topic: Topic(assessment_type=topic[0], name=topic[1], description=topic[2]), data['topic'])
    )

    for i, question_set in enumerate(data['question']):
        questions = []
        for q in question_set:
            question = Question(multiple=q[0], max_score=q[1], content=q[2], topic_id=(i + 1))
            if len(q) > 3:
                question.recommendation = q[3]
            questions.append(question)

        Question.objects.bulk_create(questions)

    answers = list(data['answer'])
    for i in range(46): # Cyber Essential Question Count
        answers.append(((1, 'Yes'), (0, 'No')))

    for i, question in enumerate(answers):
        Answer.objects.bulk_create(
            map(lambda ans: Answer(content=ans[1], score=ans[0], question_id=(i + 1)), question)
        )
