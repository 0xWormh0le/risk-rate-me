# Generated by Django 2.2.3 on 2019-11-28 13:37

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import django_countries.fields


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(default='example.com', max_length=255, unique=True)),
                ('tags', models.TextField(blank=True, default='')),
            ],
        ),
        migrations.CreateModel(
            name='RiskReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('generated_on', models.DateTimeField(default=django.utils.timezone.now)),
                ('latest', models.BooleanField(default=True)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reports.Domain')),
            ],
        ),
        migrations.CreateModel(
            name='ScoreItem',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(default='', max_length=64)),
                ('score', models.DecimalField(decimal_places=4, default=0.0, max_digits=7)),
                ('rating', models.CharField(default='Z', max_length=1)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reports.RiskReport')),
            ],
        ),
        migrations.CreateModel(
            name='TestDefinition',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(max_length=128, unique=True)),
                ('name', models.CharField(default='', max_length=128, unique=True)),
                ('description', models.TextField(blank=True, default='', max_length=512)),
                ('category', models.TextField(default='', max_length=256)),
                ('keywords', models.TextField(blank=True, default='', max_length=256)),
                ('weight', models.DecimalField(decimal_places=4, default=1.0, max_digits=7)),
                ('passing_score', models.DecimalField(decimal_places=4, default=1.0, max_digits=7)),
                ('failing_score', models.DecimalField(decimal_places=4, default=0.0, max_digits=7)),
                ('information_only', models.BooleanField(default=False)),
                ('score_failed', models.DecimalField(decimal_places=4, default=0.0, max_digits=7)),
                ('score_partial', models.DecimalField(decimal_places=4, default=0.5, max_digits=7)),
                ('score_success', models.DecimalField(decimal_places=4, default=1.0, max_digits=7)),
                ('score_error', models.DecimalField(decimal_places=4, default=0.0, max_digits=7)),
                ('score_na', models.DecimalField(decimal_places=4, default=0.0, max_digits=7)),
                ('message_failed', models.TextField(blank=True, default='', max_length=1024)),
                ('message_partial', models.TextField(blank=True, default='', max_length=1024)),
                ('message_success', models.TextField(blank=True, default='', max_length=1024)),
                ('message_error', models.TextField(blank=True, default='', max_length=512)),
                ('message_na', models.TextField(blank=True, default='', max_length=512)),
            ],
        ),
        migrations.CreateModel(
            name='TestResult',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.CharField(choices=[('failed', 'Failed'), ('partial', 'Partial'), ('error', 'Error'), ('success', 'Success'), ('na', 'Not Available')], default='na', max_length=16)),
                ('score', models.FloatField(default=0.0)),
                ('message', models.TextField(blank=True, default='', max_length=1024)),
                ('data', models.TextField(blank=True, default='', max_length=6144)),
                ('definition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reports.TestDefinition')),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reports.RiskReport')),
            ],
        ),
        migrations.AlterModelOptions(
            name='company',
            options={'verbose_name_plural': 'Companies'},
        ),
        migrations.RemoveField(
            model_name='company',
            name='address',
        ),
        migrations.AddField(
            model_name='company',
            name='city',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='company',
            name='country',
            field=django_countries.fields.CountryField(blank=True, default='', max_length=2),
        ),
        migrations.AddField(
            model_name='company',
            name='postal_code',
            field=models.CharField(blank=True, default='', max_length=10),
        ),
        migrations.AddField(
            model_name='company',
            name='region',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='company',
            name='street_1',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='company',
            name='street_2',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AlterField(
            model_name='company',
            name='sector',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='reports.Sector'),
        ),
        migrations.AlterField(
            model_name='sector',
            name='name',
            field=models.CharField(blank=True, default='', max_length=96),
        ),
        migrations.DeleteModel(
            name='Address',
        ),
        migrations.AddField(
            model_name='domain',
            name='company',
            field=models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, to='reports.Company'),
        ),
    ]
