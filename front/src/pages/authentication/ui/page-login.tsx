import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Form, FormField } from '@/components/ui/form'
import { UseFormReturn } from 'react-hook-form'
import { AuthenticateSchema } from '@/pages/authentication/feature/page-login-feature'
import { MagicCard } from '@/components/magicui/magic-card'
import { InputText } from '@/components/ui/input-text'
import { Link } from 'react-router'
import { Schemas } from '@/api/api.client'
import { useState } from 'react'
import { Mail, KeyRound } from 'lucide-react'
import RealmLoginSetting = Schemas.RealmLoginSetting

export interface PageLoginProps {
  form: UseFormReturn<AuthenticateSchema>
  onSubmit: (data: AuthenticateSchema) => void
  isError?: boolean
  loginSettings: RealmLoginSetting
}

export default function PageLogin({ form, onSubmit, isError, loginSettings }: PageLoginProps) {
  const [loginMethod, setLoginMethod] = useState<'password' | 'magic-link'>('password')

  if (isError) return <ErrorMessage />

  return (
    <div className='flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10'>
      <div className='w-full max-w-sm md:max-w-3xl'>
        <LoginCard
          form={form}
          onSubmit={onSubmit}
          loginSettings={loginSettings}
          loginMethod={loginMethod}
          setLoginMethod={setLoginMethod}
        />
      </div>
    </div>
  )
}

function LoginCard({
  form,
  onSubmit,
  loginSettings,
  loginMethod,
  setLoginMethod,
}: {
  form: UseFormReturn<AuthenticateSchema>
  onSubmit: (data: AuthenticateSchema) => void
  loginSettings: RealmLoginSetting
  loginMethod: 'password' | 'magic-link'
  setLoginMethod: (method: 'password' | 'magic-link') => void
}) {
  return (
    <Card className='overflow-hidden p-0'>
      <MagicCard className='p-0' gradientColor='#D9D9D955'>
        <CardContent className='grid p-0 md:grid-cols-2'>
          <div className='p-6 md:p-8'>
            <div className='flex flex-col gap-6'>
              <div className='flex flex-col items-center text-center'>
                <h1 className='text-2xl font-bold'>Welcome back</h1>
                <p className='text-balance text-muted-foreground'>Sign in to your account</p>
              </div>

              {loginSettings.magic_link_enabled && (
                <div className='flex gap-3 justify-center'>
                  <Button
                    type='button'
                    variant={loginMethod === 'password' ? 'default' : 'ghost'}
                    size='sm'
                    onClick={() => setLoginMethod('password')}
                  >
                    <KeyRound className='w-4 h-4 mr-2' />
                    Sign in with Password
                  </Button>
                  <span className='text-muted-foreground self-center'>OR</span>
                  <Button
                    type='button'
                    variant={loginMethod === 'magic-link' ? 'default' : 'ghost'}
                    size='sm'
                    onClick={() => setLoginMethod('magic-link')}
                  >
                    <Mail className='w-4 h-4 mr-2' />
                    Sign in with Magic Link
                  </Button>
                </div>
              )}

              {loginMethod === 'password' ? (
                <PasswordForm form={form} onSubmit={onSubmit} />
              ) : (
                <MagicLinkForm />
              )}
            </div>
          </div>
          <div className='relative hidden bg-muted md:block'>
            <img
              src='/logo_ferriskey.png'
              alt='Image'
              className='absolute inset-0 h-full w-full object-cover dark:brightness-[0.2] dark:grayscale'
            />
          </div>
        </CardContent>
      </MagicCard>
    </Card>
  )
}

function PasswordForm({
  form,
  onSubmit,
}: {
  form: UseFormReturn<AuthenticateSchema>
  onSubmit: (data: AuthenticateSchema) => void
}) {
  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className='flex flex-col gap-4'>
        <div className='grid gap-2'>
          <FormField
            control={form.control}
            name='username'
            render={({ field }) => (
              <InputText
                {...field}
                label='Username'
                name='username'
                className='w-full'
                error={form.formState.errors.username?.message}
              />
            )}
          />
        </div>
        <div className='grid gap-2'>
          <FormField
            control={form.control}
            name='password'
            render={({ field }) => (
              <InputText
                {...field}
                label='Password'
                name='password'
                type='password'
                className='w-full'
                error={form.formState.errors.password?.message}
              />
            )}
          />
        </div>
        <Button type='submit' className='w-full'>
          Sign in
        </Button>
      </form>
    </Form>
  )
}

function MagicLinkForm() {
  return (
    <div className='flex flex-col gap-4'>
      <p className='text-sm text-muted-foreground text-center'>
        No password needed. We&apos;ll send you a secure link to sign in instantly.
      </p>
      <Link to='./magic-link' className='w-full'>
        <Button type='button' className='w-full'>
          Continue with Magic Link
        </Button>
      </Link>
    </div>
  )
}

function ErrorMessage() {
  return (
    <div className='flex min-h-svh flex-col items-center justify-center'>
      <p className='text-lg font-semibold text-destructive'>An error occurred during login</p>
      <p className='text-muted-foreground'>Please try again</p>
    </div>
  )
}
